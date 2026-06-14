package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	pkgsftp "github.com/pkg/sftp"

	"github.com/nermius/nermius/internal/domain"
)

var (
	ErrSFTPDestinationExists            = errors.New("sftp destination exists")
	ErrSFTPDirectoryTransferUnsupported = errors.New("sftp directory transfer is not supported")
	ErrSFTPRecursiveRequired            = errors.New("sftp recursive flag is required")
)

type SFTPRemoteSpec struct {
	Host string
	Path string
}

type SFTPEntry struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	IsDir   bool      `json:"is_dir"`
	Size    int64     `json:"size"`
	Mode    string    `json:"mode"`
	ModTime time.Time `json:"mod_time"`
}

type SFTPTransferReport struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Bytes       int64  `json:"bytes"`
}

type SFTPPathExistsError struct {
	Path string
}

func (e *SFTPPathExistsError) Error() string {
	if e == nil || e.Path == "" {
		return ErrSFTPDestinationExists.Error()
	}
	return fmt.Sprintf("%s: %s", ErrSFTPDestinationExists, e.Path)
}

func (e *SFTPPathExistsError) Is(target error) bool {
	return target == ErrSFTPDestinationExists
}

type SFTPSession struct {
	Host domain.ResolvedConfig

	client  *pkgsftp.Client
	closers []io.Closer
	once    sync.Once
}

func (c *Connector) OpenSFTP(ctx context.Context, spec string, prompts Prompts) (*SFTPSession, error) {
	resolved, sshClient, cleanups, err := c.openClient(ctx, spec, prompts)
	if err != nil {
		return nil, err
	}
	reportProgress(prompts, "starting SFTP subsystem")
	client, err := pkgsftp.NewClient(sshClient)
	if err != nil {
		_ = closeAll(cleanups)
		return nil, err
	}
	reportProgress(prompts, "SFTP connected")
	return &SFTPSession{
		Host:    resolved,
		client:  client,
		closers: append([]io.Closer{client}, cleanups...),
	}, nil
}

func ParseSFTPRemoteSpec(spec string) (SFTPRemoteSpec, error) {
	host, remotePath, ok := strings.Cut(spec, ":")
	if !ok {
		return SFTPRemoteSpec{}, fmt.Errorf("remote path must use <host>:<path>: %q", spec)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return SFTPRemoteSpec{}, fmt.Errorf("remote path requires a host before colon: %q", spec)
	}
	return SFTPRemoteSpec{Host: host, Path: NormalizeSFTPRemotePath(remotePath)}, nil
}

func NormalizeSFTPRemotePath(remotePath string) string {
	if remotePath == "" {
		return "."
	}
	return path.Clean(remotePath)
}

func JoinSFTPRemotePath(dir, name string) string {
	dir = NormalizeSFTPRemotePath(dir)
	if dir == "." {
		return NormalizeSFTPRemotePath(name)
	}
	return NormalizeSFTPRemotePath(path.Join(dir, name))
}

func ParentSFTPRemotePath(remotePath string) string {
	remotePath = NormalizeSFTPRemotePath(remotePath)
	if remotePath == "." || remotePath == "/" {
		return remotePath
	}
	return NormalizeSFTPRemotePath(path.Dir(remotePath))
}

func BaseSFTPRemotePath(remotePath string) string {
	remotePath = NormalizeSFTPRemotePath(remotePath)
	base := path.Base(remotePath)
	if base == "." || base == "/" {
		return "download"
	}
	return base
}

func (s *SFTPSession) Close() error {
	var err error
	s.once.Do(func() {
		err = closeAll(s.closers)
	})
	return err
}

func (s *SFTPSession) ReadDir(ctx context.Context, remotePath string) ([]SFTPEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	remotePath = NormalizeSFTPRemotePath(remotePath)
	infos, err := s.client.ReadDirContext(ctx, remotePath)
	if err != nil {
		return nil, err
	}
	entries := make([]SFTPEntry, 0, len(infos))
	for _, info := range infos {
		entries = append(entries, sftpEntryFromInfo(info, JoinSFTPRemotePath(remotePath, info.Name())))
	}
	sortSFTPEntries(entries)
	return entries, nil
}

func (s *SFTPSession) Stat(ctx context.Context, remotePath string) (SFTPEntry, error) {
	if err := ctx.Err(); err != nil {
		return SFTPEntry{}, err
	}
	remotePath = NormalizeSFTPRemotePath(remotePath)
	info, err := s.client.Stat(remotePath)
	if err != nil {
		return SFTPEntry{}, err
	}
	return sftpEntryFromInfo(info, remotePath), ctx.Err()
}

func (s *SFTPSession) Mkdir(ctx context.Context, remotePath string, parents bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	remotePath = NormalizeSFTPRemotePath(remotePath)
	if parents {
		return s.client.MkdirAll(remotePath)
	}
	return s.client.Mkdir(remotePath)
}

func (s *SFTPSession) Remove(ctx context.Context, remotePath string, recursive bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	remotePath = NormalizeSFTPRemotePath(remotePath)
	if unsafeSFTPRemovalPath(remotePath) {
		return fmt.Errorf("refusing to remove unsafe remote path %q", remotePath)
	}
	info, err := s.client.Stat(remotePath)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if !recursive {
			return ErrSFTPRecursiveRequired
		}
		return s.client.RemoveAll(remotePath)
	}
	return s.client.Remove(remotePath)
}

func (s *SFTPSession) Rename(ctx context.Context, oldPath, newPath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	oldPath = NormalizeSFTPRemotePath(oldPath)
	newPath = NormalizeSFTPRemotePath(newPath)
	if _, ok := s.client.HasExtension("posix-rename@openssh.com"); ok {
		if err := s.client.PosixRename(oldPath, newPath); err == nil {
			return nil
		}
	}
	return s.client.Rename(oldPath, newPath)
}

func (s *SFTPSession) Download(ctx context.Context, remotePath, localPath string, overwrite bool) (SFTPTransferReport, error) {
	if err := ctx.Err(); err != nil {
		return SFTPTransferReport{}, err
	}
	remotePath = NormalizeSFTPRemotePath(remotePath)
	info, err := s.client.Stat(remotePath)
	if err != nil {
		return SFTPTransferReport{}, err
	}
	if info.IsDir() {
		return SFTPTransferReport{}, ErrSFTPDirectoryTransferUnsupported
	}
	destination, err := resolveDownloadDestination(remotePath, localPath)
	if err != nil {
		return SFTPTransferReport{}, err
	}
	if err := ensureLocalDestinationWritable(destination, overwrite); err != nil {
		return SFTPTransferReport{}, err
	}
	remoteFile, err := s.client.Open(remotePath)
	if err != nil {
		return SFTPTransferReport{}, err
	}
	defer remoteFile.Close()
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if !overwrite {
		flags |= os.O_EXCL
	}
	localFile, err := os.OpenFile(destination, flags, 0644)
	if err != nil {
		if os.IsExist(err) {
			return SFTPTransferReport{}, &SFTPPathExistsError{Path: destination}
		}
		return SFTPTransferReport{}, err
	}
	defer localFile.Close()
	bytes, err := copyWithContext(ctx, localFile, remoteFile)
	return SFTPTransferReport{Source: remotePath, Destination: destination, Bytes: bytes}, err
}

func (s *SFTPSession) Upload(ctx context.Context, localPath, remotePath string, overwrite bool) (SFTPTransferReport, error) {
	if err := ctx.Err(); err != nil {
		return SFTPTransferReport{}, err
	}
	info, err := os.Stat(localPath)
	if err != nil {
		return SFTPTransferReport{}, err
	}
	if info.IsDir() {
		return SFTPTransferReport{}, ErrSFTPDirectoryTransferUnsupported
	}
	destination, err := s.resolveUploadDestination(remotePath, localPath, overwrite)
	if err != nil {
		return SFTPTransferReport{}, err
	}
	localFile, err := os.Open(localPath)
	if err != nil {
		return SFTPTransferReport{}, err
	}
	defer localFile.Close()
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if !overwrite {
		flags |= os.O_EXCL
	}
	remoteFile, err := s.client.OpenFile(destination, flags)
	if err != nil {
		if os.IsExist(err) {
			return SFTPTransferReport{}, &SFTPPathExistsError{Path: destination}
		}
		return SFTPTransferReport{}, err
	}
	defer remoteFile.Close()
	bytes, err := copyWithContext(ctx, remoteFile, localFile)
	return SFTPTransferReport{Source: localPath, Destination: destination, Bytes: bytes}, err
}

func (s *SFTPSession) resolveUploadDestination(remotePath, localPath string, overwrite bool) (string, error) {
	destination := NormalizeSFTPRemotePath(remotePath)
	info, err := s.client.Stat(destination)
	if err == nil {
		if info.IsDir() {
			destination = JoinSFTPRemotePath(destination, filepath.Base(localPath))
			info, err = s.client.Stat(destination)
			if err != nil && !isPathNotExist(err) {
				return "", err
			}
		}
		if err == nil && !info.IsDir() && !overwrite {
			return "", &SFTPPathExistsError{Path: destination}
		}
		if err == nil && info.IsDir() {
			return "", ErrSFTPDirectoryTransferUnsupported
		}
		return destination, nil
	}
	if !isPathNotExist(err) {
		return "", err
	}
	return destination, nil
}

func resolveDownloadDestination(remotePath, localPath string) (string, error) {
	if strings.TrimSpace(localPath) == "" {
		return "", errors.New("local path is required")
	}
	info, err := os.Stat(localPath)
	if err == nil && info.IsDir() {
		return filepath.Join(localPath, BaseSFTPRemotePath(remotePath)), nil
	}
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	return localPath, nil
}

func ensureLocalDestinationWritable(path string, overwrite bool) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.IsDir() {
		return ErrSFTPDirectoryTransferUnsupported
	}
	if !overwrite {
		return &SFTPPathExistsError{Path: path}
	}
	return nil
}

func sftpEntryFromInfo(info os.FileInfo, remotePath string) SFTPEntry {
	return SFTPEntry{
		Name:    info.Name(),
		Path:    NormalizeSFTPRemotePath(remotePath),
		IsDir:   info.IsDir(),
		Size:    info.Size(),
		Mode:    info.Mode().String(),
		ModTime: info.ModTime(),
	}
}

func sortSFTPEntries(entries []SFTPEntry) {
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
}

func unsafeSFTPRemovalPath(remotePath string) bool {
	switch NormalizeSFTPRemotePath(remotePath) {
	case "", ".", "/":
		return true
	default:
		return false
	}
}

func isPathNotExist(err error) bool {
	if errors.Is(err, os.ErrNotExist) || os.IsNotExist(err) {
		return true
	}
	var statusErr *pkgsftp.StatusError
	return errors.As(err, &statusErr) && statusErr.FxCode() == pkgsftp.ErrSSHFxNoSuchFile
}

func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return written, ctx.Err()
			}
			return written, er
		}
	}
}
