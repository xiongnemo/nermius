package config

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type ActionKind string

const (
	// ActionMove moves a file to its new location.
	ActionMove ActionKind = "move"
	// ActionDuplicate removes a legacy file whose identical copy is already at
	// the new location.
	ActionDuplicate ActionKind = "duplicate"
	// ActionConflict leaves both copies alone because they differ.
	ActionConflict ActionKind = "conflict"
	// ActionDelete removes an obsolete legacy file that nothing reads any more.
	ActionDelete ActionKind = "delete"
	// ActionRemoveDir removes a legacy directory that is, or will be, empty.
	ActionRemoveDir ActionKind = "rmdir"
	// ActionSkip leaves a file alone and says why.
	ActionSkip ActionKind = "skip"
)

type Action struct {
	Kind   ActionKind
	Item   string
	From   string
	To     string
	Reason string
}

type MigrationPlan struct {
	Dirs Dirs
	// Checked lists the legacy directories that were looked at.
	Checked []string
	Actions []Action
}

// Pending reports whether the plan would change anything.
func (p MigrationPlan) Pending() bool {
	for _, action := range p.Actions {
		if action.Kind != ActionSkip && action.Kind != ActionConflict {
			return true
		}
	}
	return false
}

func (p MigrationPlan) Conflicts() int {
	count := 0
	for _, action := range p.Actions {
		if action.Kind == ActionConflict {
			count++
		}
	}
	return count
}

// Moves reports whether the plan moves path away.
func (p MigrationPlan) Moves(path string) (string, bool) {
	for _, action := range p.Actions {
		if action.Kind == ActionMove && samePath(action.From, path) {
			return action.To, true
		}
	}
	return "", false
}

const (
	sessionItem   = "unlock session from an old release"
	sessionReason = "it holds a plaintext copy of the vault key and no current release reads it"
	unknownReason = "not a file nermius wrote; left in place"
)

// PlanMigration works out how to move every file older releases left in their
// locations to the XDG layout. It reads the legacy and new locations but
// changes nothing.
func PlanMigration(env Env) MigrationPlan {
	roots := env.legacyRoots()
	p := &planner{
		dirs:    env.Dirs(),
		claimed: map[string]string{},
		gone:    map[string]bool{},
	}
	// Newest first, so the most recent copy of an item takes the new location
	// and older copies are compared against it.
	p.scanCacheRoot(roots.HomeCache)
	p.scanConfigRoot(roots.Home, roots.HomeCache)
	p.scanCacheRoot(roots.OSCache)
	p.scanConfigRoot(roots.OSConfig, "")
	// roots.HomeCache sits inside roots.Home, so it is cleaned up with it.
	for _, root := range []string{roots.Home, roots.OSCache, roots.OSConfig} {
		p.planRemoveIfEmpty(root)
	}
	checked := []string{}
	for _, root := range []string{roots.Home, roots.OSConfig, roots.OSCache} {
		if root != "" {
			checked = append(checked, root)
		}
	}
	return MigrationPlan{Dirs: p.dirs, Checked: checked, Actions: p.actions}
}

type planner struct {
	dirs    Dirs
	actions []Action
	// claimed maps a destination to the file this plan moves there, so later
	// copies of the same item are compared with what will be there.
	claimed map[string]string
	// gone holds every path this plan removes or moves away.
	gone map[string]bool
}

func (p *planner) add(action Action) {
	p.actions = append(p.actions, action)
}

func pathKey(path string) string {
	path = filepath.Clean(path)
	if runtime.GOOS == "windows" {
		return strings.ToLower(path)
	}
	return path
}

// current reports whether path is one of the XDG directories or contains one.
// Those are never treated as legacy, whatever the XDG variables point at.
func (p *planner) current(path string) bool {
	for _, dir := range p.dirs.all() {
		if samePath(path, dir) || isWithin(dir, path) {
			return true
		}
	}
	return false
}

// isCurrentRoot reports whether a legacy root is itself one of the XDG
// directories, as os.UserConfigDir and os.UserCacheDir are on Linux.
func (p *planner) isCurrentRoot(root string) bool {
	for _, dir := range p.dirs.all() {
		if samePath(root, dir) {
			return true
		}
	}
	return false
}

func isWithin(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func (p *planner) readRoot(root string) []os.DirEntry {
	if root == "" {
		return nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			p.add(Action{Kind: ActionSkip, From: root, Reason: err.Error()})
		}
		return nil
	}
	return entries
}

// scanConfigRoot handles ~/.nermius and os.UserConfigDir()/nermius, which held
// the vault and its backups.
func (p *planner) scanConfigRoot(root, except string) {
	for _, entry := range p.readRoot(root) {
		path := filepath.Join(root, entry.Name())
		if samePath(path, except) || p.current(path) {
			continue
		}
		if item := vaultFileItem(entry.Name()); item != "" && !entry.IsDir() {
			p.planFile(item, path, filepath.Join(p.dirs.Data, entry.Name()))
			continue
		}
		p.unknown(root, path)
	}
}

// scanCacheRoot handles ~/.nermius/cache and os.UserCacheDir()/nermius, which
// held the keychain blobs and, in the earliest releases, session.json.
func (p *planner) scanCacheRoot(root string) {
	for _, entry := range p.readRoot(root) {
		name := entry.Name()
		path := filepath.Join(root, name)
		if p.current(path) {
			continue
		}
		switch {
		case entry.IsDir() && name == KeychainDirName:
			p.planTree("keychain enrollment", path, filepath.Join(p.dirs.Data, KeychainDirName))
		case entry.IsDir() && strings.HasPrefix(name, KeychainDirName+".bak."):
			p.planTree("keychain backup", path, filepath.Join(p.dirs.Data, name))
		case !entry.IsDir() && strings.HasPrefix(name, "session.json"):
			p.add(Action{Kind: ActionDelete, Item: sessionItem, From: path, Reason: sessionReason})
			p.gone[pathKey(path)] = true
		default:
			p.unknown(root, path)
		}
	}
}

// vaultFileItem names the vault files nermius wrote next to vault.db: the
// database, SQLite's journal, and the backups `vault migrate` made.
func vaultFileItem(name string) string {
	switch {
	case name == DefaultVaultName:
		return "vault"
	case strings.HasPrefix(name, DefaultVaultName+"-"):
		return "vault journal"
	case strings.HasPrefix(name, DefaultVaultName+".bak."):
		return "vault backup"
	}
	return ""
}

func (p *planner) unknown(root, path string) {
	if p.isCurrentRoot(root) {
		// Other files in a directory that is also a current XDG directory
		// belong to the current layout, not to an older release.
		return
	}
	p.add(Action{Kind: ActionSkip, From: path, Reason: unknownReason})
}

func (p *planner) planTree(item, src, dst string) {
	err := filepath.WalkDir(src, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			p.add(Action{Kind: ActionSkip, Item: item, From: path, Reason: walkErr.Error()})
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		p.planFile(item, path, filepath.Join(dst, rel))
		return nil
	})
	if err != nil {
		p.add(Action{Kind: ActionSkip, Item: item, From: src, Reason: err.Error()})
	}
}

func (p *planner) planFile(item, src, dst string) {
	if samePath(src, dst) {
		return
	}
	info, err := os.Lstat(src)
	if err != nil {
		p.add(Action{Kind: ActionSkip, Item: item, From: src, Reason: err.Error()})
		return
	}
	if !info.Mode().IsRegular() && info.Mode()&fs.ModeSymlink == 0 {
		p.add(Action{Kind: ActionSkip, Item: item, From: src, Reason: "not a regular file; left in place"})
		return
	}
	occupant, claimed := p.claimed[pathKey(dst)]
	if !claimed {
		if _, err := os.Lstat(dst); errors.Is(err, fs.ErrNotExist) {
			p.claimed[pathKey(dst)] = src
			p.gone[pathKey(src)] = true
			p.add(Action{Kind: ActionMove, Item: item, From: src, To: dst})
			return
		} else if err != nil {
			p.add(Action{Kind: ActionSkip, Item: item, From: src, Reason: err.Error()})
			return
		}
		occupant = dst
	}
	same, err := sameContent(src, occupant)
	if err != nil {
		p.add(Action{Kind: ActionSkip, Item: item, From: src, Reason: err.Error()})
		return
	}
	if same {
		p.gone[pathKey(src)] = true
		p.add(Action{Kind: ActionDuplicate, Item: item, From: src, To: dst})
		return
	}
	p.add(Action{Kind: ActionConflict, Item: item, From: src, To: dst})
}

// planRemoveIfEmpty plans removing dir and its subdirectories once everything
// in them has gone, deepest first. It reports whether dir will be removed.
func (p *planner) planRemoveIfEmpty(dir string) bool {
	if dir == "" || p.current(dir) {
		return false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	empty := true
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			if !p.planRemoveIfEmpty(path) {
				empty = false
			}
			continue
		}
		if !p.gone[pathKey(path)] {
			empty = false
		}
	}
	if empty {
		p.gone[pathKey(dir)] = true
		p.add(Action{Kind: ActionRemoveDir, From: dir})
	}
	return empty
}

// MigrationResult counts what went wrong while executing a plan.
type MigrationResult struct {
	Conflicts int
	Failures  int
}

// DescribePlanned renders an action for --dry-run.
func DescribePlanned(action Action) string {
	switch action.Kind {
	case ActionMove:
		return fmt.Sprintf("move     %s: %s -> %s", action.Item, action.From, action.To)
	case ActionDuplicate:
		return fmt.Sprintf("remove   %s %s: an identical copy is already at %s", action.Item, action.From, action.To)
	case ActionConflict:
		return fmt.Sprintf("conflict %s: %s differs from %s; both will be kept", action.Item, action.From, action.To)
	case ActionDelete:
		return fmt.Sprintf("delete   %s %s: %s", action.Item, action.From, action.Reason)
	case ActionRemoveDir:
		return fmt.Sprintf("rmdir    %s: empty once the files above have moved", action.From)
	default:
		return fmt.Sprintf("skip     %s: %s", action.From, action.Reason)
	}
}

// Execute performs the plan, printing each action to out. It carries on past
// conflicts and failures and counts them.
func (p MigrationPlan) Execute(out io.Writer) MigrationResult {
	result := MigrationResult{}
	for _, action := range p.Actions {
		switch action.Kind {
		case ActionMove:
			executeMove(out, action, &result)
		case ActionDuplicate:
			executeDuplicate(out, action, &result)
		case ActionConflict:
			result.Conflicts++
			fmt.Fprintf(out, "conflict: %s %s differs from %s; kept both\n", action.Item, action.From, action.To)
		case ActionDelete:
			if err := os.Remove(action.From); err != nil && !errors.Is(err, fs.ErrNotExist) {
				result.Failures++
				fmt.Fprintf(out, "failed to delete %s: %v\n", action.From, err)
				continue
			}
			fmt.Fprintf(out, "deleted %s %s: %s\n", action.Item, action.From, action.Reason)
		case ActionRemoveDir:
			if err := os.Remove(action.From); err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					fmt.Fprintf(out, "left %s in place: %v\n", action.From, err)
				}
				continue
			}
			fmt.Fprintf(out, "removed empty directory %s\n", action.From)
		default:
			fmt.Fprintf(out, "skipped %s: %s\n", action.From, action.Reason)
		}
	}
	return result
}

func executeMove(out io.Writer, action Action, result *MigrationResult) {
	// Something may have appeared at the destination since the plan was made.
	if _, err := os.Lstat(action.To); err == nil {
		same, err := sameContent(action.From, action.To)
		switch {
		case err != nil:
			result.Failures++
			fmt.Fprintf(out, "failed to compare %s with %s: %v\n", action.From, action.To, err)
		case same:
			executeDuplicate(out, action, result)
		default:
			result.Conflicts++
			fmt.Fprintf(out, "conflict: %s %s differs from %s; kept both\n", action.Item, action.From, action.To)
		}
		return
	}
	if err := os.MkdirAll(filepath.Dir(action.To), 0o700); err != nil {
		result.Failures++
		fmt.Fprintf(out, "failed to move %s: %v\n", action.From, err)
		return
	}
	if err := moveFile(action.From, action.To); err != nil {
		result.Failures++
		fmt.Fprintf(out, "failed to move %s: %v\n", action.From, err)
		return
	}
	fmt.Fprintf(out, "moved %s: %s -> %s\n", action.Item, action.From, action.To)
}

func executeDuplicate(out io.Writer, action Action, result *MigrationResult) {
	if err := os.Remove(action.From); err != nil && !errors.Is(err, fs.ErrNotExist) {
		result.Failures++
		fmt.Fprintf(out, "failed to remove %s: %v\n", action.From, err)
		return
	}
	fmt.Fprintf(out, "removed %s %s: an identical copy is already at %s\n", action.Item, action.From, action.To)
}

// moveFile renames src to dst, or, where rename fails (across volumes, say),
// copies it, verifies the copy and then removes src. It never overwrites dst.
func moveFile(src, dst string) error {
	if _, err := os.Lstat(dst); err == nil {
		return fmt.Errorf("%s already exists", dst)
	}
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if err := copyVerified(src, dst); err != nil {
		_ = os.Remove(dst)
		return err
	}
	if err := os.Remove(src); err != nil {
		// Leave exactly one copy: the original.
		_ = os.Remove(dst)
		return fmt.Errorf("copied it but could not remove the original, so the copy was removed again (is nermius still running?): %w", err)
	}
	return nil
}

// copyVerified copies src to dst preserving mode and modification time, then
// checks the copy's size and SHA-256 against what was read.
func copyVerified(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		target, err := os.Readlink(src)
		if err != nil {
			return err
		}
		return os.Symlink(target, dst)
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	mode := info.Mode().Perm()
	output, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(output, hash), in)
	if err == nil {
		err = output.Sync()
	}
	if closeErr := output.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Chmod(dst, mode); err != nil {
		return err
	}
	if err := os.Chtimes(dst, info.ModTime(), info.ModTime()); err != nil {
		return err
	}
	size, sum, err := fileDigest(dst)
	if err != nil {
		return err
	}
	if size != written || size != info.Size() || !bytes.Equal(sum, hash.Sum(nil)) {
		return fmt.Errorf("the copy at %s does not match %s", dst, src)
	}
	return nil
}

func fileDigest(path string) (int64, []byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, nil, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return 0, nil, err
	}
	return size, hash.Sum(nil), nil
}

// sameContent compares two files by size and SHA-256, or two symlinks by target.
func sameContent(left, right string) (bool, error) {
	leftInfo, err := os.Lstat(left)
	if err != nil {
		return false, err
	}
	rightInfo, err := os.Lstat(right)
	if err != nil {
		return false, err
	}
	leftLink := leftInfo.Mode()&fs.ModeSymlink != 0
	rightLink := rightInfo.Mode()&fs.ModeSymlink != 0
	if leftLink || rightLink {
		if leftLink != rightLink {
			return false, nil
		}
		leftTarget, err := os.Readlink(left)
		if err != nil {
			return false, err
		}
		rightTarget, err := os.Readlink(right)
		if err != nil {
			return false, err
		}
		return leftTarget == rightTarget, nil
	}
	if !leftInfo.Mode().IsRegular() || !rightInfo.Mode().IsRegular() || leftInfo.Size() != rightInfo.Size() {
		return false, nil
	}
	_, leftSum, err := fileDigest(left)
	if err != nil {
		return false, err
	}
	_, rightSum, err := fileDigest(right)
	if err != nil {
		return false, err
	}
	return bytes.Equal(leftSum, rightSum), nil
}
