package termius

import (
	"bytes"
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"
)

type buildOptions struct {
	includeSecrets bool
	rawOnly        bool
}

func BuildBundle(blobs []EncryptedBlob, decrypted []DecryptedObject, includeSecrets bool, rawOnly bool) Bundle {
	opts := buildOptions{includeSecrets: includeSecrets, rawOnly: rawOnly}
	bundle := Bundle{
		Source:        SourceName,
		FormatVersion: BundleFormatVersion,
		Stats: Stats{
			EncryptedBlobs: len(blobs),
			DecryptedBlobs: len(decrypted),
		},
	}
	for _, item := range decrypted {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(item.Plaintext))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			addTextPayload(&bundle, item, opts)
			continue
		}
		bundle.Stats.JSONPayloads++
		addJSONValue(&bundle, item, "", value, opts)
	}
	addStoreBasedObjects(&bundle.Normalized, decrypted, opts)
	linkHostKeys(&bundle.Normalized)
	deriveGroupsFromHosts(&bundle.Normalized)
	return bundle
}

func addTextPayload(bundle *Bundle, item DecryptedObject, opts buildOptions) {
	text := strings.TrimSpace(string(item.Plaintext))
	if text == "" {
		return
	}
	rawType := classifyTextPayload(item.Field, text)
	raw := RawObject{
		Hash:          item.Hash,
		SourceFile:    item.SourceFile,
		StoreName:     item.StoreName,
		Type:          rawType,
		Field:         item.Field,
		ContextFields: item.ContextFields,
	}
	if opts.includeSecrets {
		if rawValue, err := json.Marshal(text); err == nil {
			raw.Value = rawValue
		}
	}
	bundle.RawObjects = append(bundle.RawObjects, raw)
	bundle.Stats.TextPayloads++
	if opts.rawOnly {
		return
	}
	addNormalizedTextPayload(&bundle.Normalized, item, rawType, text, opts)
}

func addNormalizedTextPayload(normalized *Normalized, item DecryptedObject, rawType string, text string, opts buildOptions) {
	if item.StoreName != "" {
		switch item.StoreName {
		case "keys", "snippets", "ssh_identities", "groups", "tags", "hosts", "history_commands", "known_hosts", "activities":
			return
		}
	}
	switch rawType {
	case "private_key":
		key := Key{
			RawHash: item.Hash,
			Name:    "termius-key-" + shortDisplayHash(item.Hash),
		}
		if opts.includeSecrets {
			key.PrivateKeyPEM = text
		}
		normalized.Keys = append(normalized.Keys, key)
	case "snippet_script":
		snippet := Snippet{
			RawHash: item.Hash,
			Label:   "termius-snippet-" + shortDisplayHash(item.Hash),
		}
		if opts.includeSecrets {
			snippet.Script = text
		}
		normalized.Snippets = append(normalized.Snippets, snippet)
	case "password", "passphrase":
		password := Password{
			RawHash:    item.Hash,
			SourceFile: item.SourceFile,
			Field:      item.Field,
			Label:      "termius-" + rawType + "-" + shortDisplayHash(item.Hash),
		}
		if opts.includeSecrets {
			password.Value = text
		}
		normalized.Passwords = append(normalized.Passwords, password)
	}
}

type recordTextFields struct {
	source        string
	storeName     string
	byField       map[string][]DecryptedObject
	contextFields map[string]struct{}
}

func addStoreBasedObjects(normalized *Normalized, decrypted []DecryptedObject, opts buildOptions) {
	records := collectFieldRecords(decrypted)
	sources := make([]string, 0, len(records))
	for source := range records {
		sources = append(sources, source)
	}
	slices.Sort(sources)
	for _, source := range sources {
		record := records[source]
		switch record.storeName {
		case "hosts":
			addStoreBasedHost(normalized, record, opts)
		case "groups", "tags":
			addStoreBasedGroup(normalized, record, opts)
		case "ssh_identities":
			addStoreBasedIdentity(normalized, record, opts)
		case "keys":
			addStoreBasedKey(normalized, record, opts)
		case "snippets":
			addStoreBasedSnippet(normalized, record, opts)
		}
	}
}

func addStoreBasedHost(normalized *Normalized, record *recordTextFields, opts buildOptions) {
	address := firstRecordField(record, "address")
	if address == nil {
		return
	}
	hash := address.Hash
	host := Host{
		RawHash: hash,
		Label:   "termius-host-" + shortDisplayHash(hash),
	}
	if opts.includeSecrets {
		host.Host = strings.TrimSpace(string(address.Plaintext))
		if label := firstRecordField(record, "label"); label != nil && strings.TrimSpace(string(label.Plaintext)) != "" {
			host.Label = strings.TrimSpace(string(label.Plaintext))
		} else if host.Host != "" {
			host.Label = host.Host
		}
	}
	if host.Host == "" && opts.includeSecrets {
		return
	}
	normalized.Hosts = append(normalized.Hosts, host)
}

func addStoreBasedGroup(normalized *Normalized, record *recordTextFields, opts buildOptions) {
	seen := map[string]struct{}{}
	for _, group := range normalized.Groups {
		if group.Name != "" {
			seen[strings.ToLower(group.Name)] = struct{}{}
		}
	}
	label := firstRecordField(record, "label")
	if label == nil {
		return
	}
	group := Group{
		RawHash: label.Hash,
		Name:    "termius-group-" + shortDisplayHash(label.Hash),
	}
	if opts.includeSecrets {
		group.Name = strings.TrimSpace(string(label.Plaintext))
	}
	if group.Name == "" {
		return
	}
	key := strings.ToLower(group.Name)
	if _, ok := seen[key]; ok {
		return
	}
	normalized.Groups = append(normalized.Groups, group)
}

func addStoreBasedIdentity(normalized *Normalized, record *recordTextFields, opts buildOptions) {
	password := firstRecordField(record, "password")
	username := firstRecordField(record, "username")
	if password == nil || username == nil {
		return
	}
	hash := password.Hash
	identity := Identity{
		RawHash: hash,
		Name:    "termius-identity-" + shortDisplayHash(hash),
	}
	if opts.includeSecrets {
		usernameText := strings.TrimSpace(string(username.Plaintext))
		label := ""
		if labelItem := firstRecordField(record, "label"); labelItem != nil {
			label = strings.TrimSpace(string(labelItem.Plaintext))
		}
		if label != "" {
			identity.Name = label
		} else if usernameText != "" {
			identity.Name = usernameText
		}
		identity.Username = usernameText
		identity.Password = strings.TrimSpace(string(password.Plaintext))
	}
	normalized.Identities = append(normalized.Identities, identity)
}

func addStoreBasedKey(normalized *Normalized, record *recordTextFields, opts buildOptions) {
	privateKey := firstRecordField(record, "private_key")
	publicKey := firstRecordField(record, "public_key")
	if privateKey == nil && publicKey == nil {
		return
	}
	hash := ""
	if privateKey != nil {
		hash = privateKey.Hash
	} else {
		hash = publicKey.Hash
	}
	key := Key{
		RawHash: hash,
		Name:    "termius-key-" + shortDisplayHash(hash),
	}
	if opts.includeSecrets {
		if label := firstRecordField(record, "label"); label != nil && strings.TrimSpace(string(label.Plaintext)) != "" {
			key.Name = strings.TrimSpace(string(label.Plaintext))
		}
		if privateKey != nil {
			key.PrivateKeyPEM = strings.TrimSpace(string(privateKey.Plaintext))
		}
		if publicKey != nil {
			key.PublicKey = strings.TrimSpace(string(publicKey.Plaintext))
		}
		if passphrase := firstRecordField(record, "passphrase"); passphrase != nil {
			key.Passphrase = strings.TrimSpace(string(passphrase.Plaintext))
		}
	}
	normalized.Keys = append(normalized.Keys, key)
}

func addStoreBasedSnippet(normalized *Normalized, record *recordTextFields, opts buildOptions) {
	script := firstRecordField(record, "script")
	if script == nil {
		return
	}
	snippet := Snippet{
		RawHash: script.Hash,
		Label:   "termius-snippet-" + shortDisplayHash(script.Hash),
	}
	if opts.includeSecrets {
		if label := firstRecordField(record, "label"); label != nil && strings.TrimSpace(string(label.Plaintext)) != "" {
			snippet.Label = strings.TrimSpace(string(label.Plaintext))
		}
		snippet.Script = strings.TrimSpace(string(script.Plaintext))
	}
	normalized.Snippets = append(normalized.Snippets, snippet)
}

func collectFieldRecords(decrypted []DecryptedObject) map[string]*recordTextFields {
	records := map[string]*recordTextFields{}
	for _, item := range decrypted {
		field := strings.ToLower(item.Field)
		if field == "" && item.StoreName != "" && looksLikeContextLabel(item) {
			field = "label"
		}
		if field == "" {
			continue
		}
		source := recordSource(item.SourceFile)
		if source == "" {
			source = item.SourceFile
		}
		if source == "" {
			continue
		}
		text := strings.TrimSpace(string(item.Plaintext))
		if text == "" {
			continue
		}
		record := records[source]
		if record == nil {
			record = &recordTextFields{
				source:        source,
				storeName:     item.StoreName,
				byField:       map[string][]DecryptedObject{},
				contextFields: map[string]struct{}{},
			}
			records[source] = record
		}
		if record.storeName == "" {
			record.storeName = item.StoreName
		}
		record.byField[field] = append(record.byField[field], item)
		for _, contextField := range item.ContextFields {
			record.contextFields[strings.ToLower(contextField)] = struct{}{}
		}
	}
	return records
}

func looksLikeContextLabel(item DecryptedObject) bool {
	text := strings.TrimSpace(string(item.Plaintext))
	if text == "" || len(text) > 128 {
		return false
	}
	if looksLikePrivateKey(text) || looksLikePublicKey(text) || looksLikeSnippetScript(text) {
		return false
	}
	context := map[string]struct{}{}
	for _, field := range item.ContextFields {
		context[strings.ToLower(field)] = struct{}{}
	}
	if _, ok := context["label"]; !ok {
		return false
	}
	for _, field := range []string{"address", "script", "username", "password", "private_key", "public_key", "passphrase"} {
		if _, ok := context[field]; ok {
			return false
		}
	}
	return true
}

func firstRecordField(record *recordTextFields, field string) *DecryptedObject {
	items := record.byField[strings.ToLower(field)]
	if len(items) == 0 {
		return nil
	}
	return &items[0]
}

func recordSource(sourceFile string) string {
	idx := strings.Index(sourceFile, "/record:")
	if idx < 0 {
		return ""
	}
	for _, suffix := range []string{":binary-value", ":binary-key", ":value", ":key"} {
		sourceFile = strings.TrimSuffix(sourceFile, suffix)
	}
	return sourceFile
}

func addJSONValue(bundle *Bundle, item DecryptedObject, jsonPath string, value any, opts buildOptions) {
	switch typed := value.(type) {
	case map[string]any:
		addJSONObject(bundle, item, jsonPath, typed, opts)
	case []any:
		for idx, child := range typed {
			childPath := jsonPath + "[" + strconv.Itoa(idx) + "]"
			bundle.Stats.JSONArrayItems++
			addJSONValue(bundle, item, childPath, child, opts)
		}
	default:
		rawType := classifyJSONScalarWithField(item.Field, typed)
		raw := RawObject{
			Hash:          rawHash(item.Hash, jsonPath),
			SourceFile:    item.SourceFile,
			StoreName:     item.StoreName,
			Type:          rawType,
			Field:         item.Field,
			ContextFields: item.ContextFields,
			JSONPath:      jsonPath,
		}
		if opts.includeSecrets {
			if rawValue, err := json.Marshal(typed); err == nil {
				raw.Value = rawValue
			}
		}
		bundle.RawObjects = append(bundle.RawObjects, raw)
		if !opts.rawOnly && (rawType == "password" || rawType == "passphrase") {
			password := Password{
				RawHash:    item.Hash,
				SourceFile: item.SourceFile,
				Field:      item.Field,
				Label:      "termius-" + rawType + "-" + shortDisplayHash(item.Hash),
			}
			if opts.includeSecrets {
				password.Value = scalarText(typed)
			}
			bundle.Normalized.Passwords = append(bundle.Normalized.Passwords, password)
		}
	}
}

func addJSONObject(bundle *Bundle, item DecryptedObject, jsonPath string, obj map[string]any, opts buildOptions) {
	if len(obj) == 0 {
		return
	}
	rawType := classifyObjectForItem(item, obj)
	fields := sortedFields(obj)
	hash := rawHash(item.Hash, jsonPath)
	raw := RawObject{
		Hash:          hash,
		SourceFile:    item.SourceFile,
		StoreName:     item.StoreName,
		Type:          rawType,
		Field:         item.Field,
		ContextFields: item.ContextFields,
		JSONPath:      jsonPath,
		Fields:        fields,
	}
	if opts.includeSecrets {
		if rawValue, err := json.Marshal(obj); err == nil {
			raw.Value = rawValue
		}
	}
	bundle.RawObjects = append(bundle.RawObjects, raw)
	bundle.Stats.JSONObjects++
	if rawType == "unknown" {
		bundle.Stats.UnknownObjects++
	}
	if opts.rawOnly {
		return
	}
	addNormalizedObject(&bundle.Normalized, hash, rawType, obj, fields, opts)
}

func addNormalizedObject(normalized *Normalized, hash string, rawType string, obj map[string]any, fields []string, opts buildOptions) {
	switch rawType {
	case "host":
		tags := firstStringSlice(obj, "tags", "tag_ids", "tagIds")
		host := Host{
			TermiusID:  firstString(obj, "id", "_id", "uuid"),
			RawHash:    hash,
			Label:      firstString(obj, "title", "label", "name"),
			Host:       firstString(obj, "host", "hostname", "address"),
			Port:       firstInt(obj, "port"),
			Username:   firstString(obj, "user_name", "username", "user"),
			KeyID:      firstString(obj, "key_id", "keyId"),
			OS:         firstString(obj, "host_os_name", "os", "platform"),
			Tags:       tags,
			GroupNames: tags,
		}
		if opts.includeSecrets {
			host.Password = firstString(obj, "password")
		}
		normalized.Hosts = append(normalized.Hosts, host)
	case "group":
		group := Group{
			TermiusID: firstString(obj, "id", "_id", "uuid", "tag_id", "tagId"),
			RawHash:   hash,
			Name:      firstString(obj, "label", "name", "title"),
		}
		if group.Name != "" {
			normalized.Groups = append(normalized.Groups, group)
		}
	case "identity":
		identity := Identity{
			TermiusID: firstString(obj, "id", "_id", "uuid"),
			RawHash:   hash,
			Name:      firstString(obj, "label", "name", "title", "username"),
			Username:  firstString(obj, "username", "user_name", "user"),
		}
		if opts.includeSecrets {
			identity.Password = firstString(obj, "password")
		}
		normalized.Identities = append(normalized.Identities, identity)
	case "key":
		key := Key{
			TermiusID:   firstString(obj, "id", "_id", "uuid"),
			RawHash:     hash,
			Name:        firstString(obj, "label", "name", "title"),
			Fingerprint: firstString(obj, "fingerprint"),
			PublicKey:   firstString(obj, "public_key", "publicKey"),
		}
		if opts.includeSecrets {
			key.PrivateKeyPEM = firstString(obj, "private_key", "privateKey", "private_key_pem")
			key.Passphrase = firstString(obj, "passphrase")
		}
		normalized.Keys = append(normalized.Keys, key)
	case "forward":
		forward := Forward{
			TermiusID:  firstString(obj, "id", "_id", "uuid", "forward_id", "forwardId"),
			RawHash:    hash,
			Name:       firstString(obj, "label", "name", "title"),
			HostID:     firstString(obj, "host_id", "hostId", "source_host_id", "sourceHostId"),
			HostName:   firstString(obj, "host", "hostname", "host_name", "hostName"),
			Type:       firstString(obj, "type", "forward_type", "forwardType", "connection_type"),
			ListenHost: firstString(obj, "listen_host", "listenHost", "source_host", "sourceHost", "local_address", "localAddress"),
			ListenPort: firstInt(obj, "listen_port", "listenPort", "source_port", "sourcePort", "local_port", "localPort"),
			TargetHost: firstString(obj, "target_host", "targetHost", "destination_host", "destinationHost", "remote_host", "remoteHost"),
			TargetPort: firstInt(obj, "target_port", "targetPort", "destination_port", "destinationPort", "remote_port", "remotePort"),
		}
		normalized.Forwards = append(normalized.Forwards, forward)
	case "snippet":
		snippet := Snippet{
			TermiusID: firstString(obj, "id", "_id", "uuid"),
			RawHash:   hash,
			Label:     firstString(obj, "label", "name", "title"),
		}
		if opts.includeSecrets {
			snippet.Script = firstString(obj, "script")
		}
		normalized.Snippets = append(normalized.Snippets, snippet)
	case "unknown":
		normalized.UnknownRefs = append(normalized.UnknownRefs, UnknownRef{
			RawHash: hash,
			Type:    rawType,
			Fields:  fields,
		})
	}
}

func classifyObjectForItem(item DecryptedObject, obj map[string]any) string {
	switch item.StoreName {
	case "hosts":
		return "host"
	case "groups", "tags":
		return "group"
	case "ssh_identities":
		return "identity"
	case "keys":
		return "key"
	case "snippets":
		return "snippet"
	case "pf_rules":
		return "forward"
	case "activities":
		return "activity"
	case "history_commands":
		return "history_command"
	case "known_hosts":
		return "known_host"
	}
	return classifyObject(obj)
}

func classifyObject(obj map[string]any) string {
	switch {
	case firstString(obj, "private_key", "privateKey", "private_key_pem") != "" && firstString(obj, "label", "name", "title") != "":
		return "key"
	case firstString(obj, "host", "hostname", "address") != "" && firstString(obj, "user_name", "username", "user") != "":
		return "host"
	case looksLikeForward(obj):
		return "forward"
	case firstString(obj, "username", "user_name", "user") != "" && hasAny(obj, "password"):
		return "identity"
	case firstString(obj, "script") != "" && firstString(obj, "label", "name", "title") != "":
		return "snippet"
	case looksLikeGroup(obj):
		return "group"
	default:
		return "unknown"
	}
}

func classifyTextPayload(field string, text string) string {
	switch {
	case strings.EqualFold(field, "password"):
		return "password"
	case strings.EqualFold(field, "passphrase"):
		return "passphrase"
	case strings.EqualFold(field, "private_key"):
		return "private_key"
	case strings.EqualFold(field, "public_key"):
		return "public_key"
	case strings.EqualFold(field, "script"):
		return "snippet_script"
	case looksLikePrivateKey(text):
		return "private_key"
	case looksLikePublicKey(text):
		return "public_key"
	case looksLikeSnippetScript(text):
		return "snippet_script"
	case looksLikeSecretText(text):
		return "secret_text"
	default:
		return "text"
	}
}

func looksLikePrivateKey(text string) bool {
	return strings.Contains(text, "BEGIN OPENSSH PRIVATE KEY") ||
		strings.Contains(text, "BEGIN RSA PRIVATE KEY") ||
		strings.Contains(text, "BEGIN DSA PRIVATE KEY") ||
		strings.Contains(text, "BEGIN EC PRIVATE KEY") ||
		strings.Contains(text, "BEGIN PRIVATE KEY")
}

func looksLikePublicKey(text string) bool {
	return strings.HasPrefix(text, "ssh-rsa ") ||
		strings.HasPrefix(text, "ssh-ed25519 ") ||
		strings.HasPrefix(text, "ecdsa-sha2-")
}

func looksLikeSnippetScript(text string) bool {
	lower := strings.ToLower(text)
	if fields := strings.Fields(lower); len(fields) > 0 {
		switch fields[0] {
		case "sudo", "systemctl", "docker", "kubectl", "kill", "echo", "python", "python3", "bash", "sh":
			return true
		}
	}
	if !strings.ContainsAny(text, "\n;&|`$") {
		return false
	}
	for _, token := range []string{"sudo", "ssh", "systemctl", "docker", "kubectl", "kill", "echo", "cd ", "ls ", "cat ", "python", "bash"} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func looksLikeSecretText(text string) bool {
	if strings.Contains(text, "\n") || looksLikePublicKey(text) {
		return false
	}
	return len(text) > 0 && len(text) <= 256
}

func linkHostKeys(normalized *Normalized) {
	keysByTermiusID := map[string]string{}
	keysByName := map[string]string{}
	for _, key := range normalized.Keys {
		if key.TermiusID != "" && key.Name != "" {
			keysByTermiusID[key.TermiusID] = key.Name
		}
		if key.Name != "" {
			keysByName[strings.ToLower(key.Name)] = key.Name
		}
	}
	for i := range normalized.Hosts {
		host := &normalized.Hosts[i]
		if host.KeyID == "" || host.KeyName != "" {
			continue
		}
		if name := keysByTermiusID[host.KeyID]; name != "" {
			host.KeyName = name
			continue
		}
		if name := keysByName[strings.ToLower(host.KeyID)]; name != "" {
			host.KeyName = name
		}
	}
}

func shortDisplayHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}

func deriveGroupsFromHosts(normalized *Normalized) {
	seen := map[string]struct{}{}
	for _, group := range normalized.Groups {
		seen[strings.ToLower(group.Name)] = struct{}{}
	}
	for _, host := range normalized.Hosts {
		for _, tag := range host.GroupNames {
			tag = strings.TrimSpace(tag)
			if tag == "" {
				continue
			}
			key := strings.ToLower(tag)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			normalized.Groups = append(normalized.Groups, Group{Name: tag})
		}
	}
	slices.SortFunc(normalized.Groups, func(left, right Group) int {
		return strings.Compare(strings.ToLower(left.Name), strings.ToLower(right.Name))
	})
}

func sortedFields(obj map[string]any) []string {
	fields := slices.Collect(maps.Keys(obj))
	slices.Sort(fields)
	return fields
}

func hasAny(obj map[string]any, keys ...string) bool {
	for _, key := range keys {
		if _, ok := obj[key]; ok {
			return true
		}
	}
	return false
}

func looksLikeGroup(obj map[string]any) bool {
	if firstString(obj, "label", "name", "title") == "" {
		return false
	}
	return hasAny(obj, "tag_id", "tagId", "parent_id", "parentId", "children", "hosts", "host_ids", "hostIds")
}

func looksLikeForward(obj map[string]any) bool {
	if hasAny(obj, "local_port", "localPort", "remote_port", "remotePort", "listen_port", "listenPort", "source_port", "sourcePort", "target_port", "targetPort", "destination_port", "destinationPort") {
		return hasAny(obj, "host_id", "hostId", "source_host_id", "sourceHostId", "destination_host", "destinationHost", "target_host", "targetHost", "remote_host", "remoteHost")
	}
	rawType := strings.ToLower(firstString(obj, "type", "forward_type", "forwardType", "connection_type"))
	return strings.Contains(rawType, "forward") || strings.Contains(rawType, "tunnel")
}

func classifyJSONScalar(value any) string {
	switch value.(type) {
	case string:
		return "json_string"
	case json.Number:
		return "json_number"
	case bool:
		return "json_bool"
	case nil:
		return "json_null"
	default:
		return "json_value"
	}
}

func classifyJSONScalarWithField(field string, value any) string {
	switch {
	case strings.EqualFold(field, "password"):
		return "password"
	case strings.EqualFold(field, "passphrase"):
		return "passphrase"
	default:
		return classifyJSONScalar(value)
	}
}

func scalarText(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func firstString(obj map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := obj[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return typed
			}
		case json.Number:
			if typed.String() != "" {
				return typed.String()
			}
		}
	}
	return ""
}

func firstStringSlice(obj map[string]any, keys ...string) []string {
	for _, key := range keys {
		value, ok := obj[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case []any:
			out := []string{}
			for _, item := range typed {
				switch inner := item.(type) {
				case string:
					if strings.TrimSpace(inner) != "" {
						out = append(out, inner)
					}
				case map[string]any:
					if label := firstString(inner, "label", "name", "title", "id", "_id", "uuid"); label != "" {
						out = append(out, label)
					}
				}
			}
			return out
		case []string:
			return append([]string(nil), typed...)
		case string:
			if strings.TrimSpace(typed) != "" {
				return []string{typed}
			}
		}
	}
	return nil
}

func firstInt(obj map[string]any, keys ...string) int {
	for _, key := range keys {
		value, ok := obj[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case float64:
			return int(typed)
		case int:
			return typed
		case json.Number:
			if parsed, err := strconv.Atoi(typed.String()); err == nil {
				return parsed
			}
		case string:
			if parsed, err := strconv.Atoi(strings.TrimSpace(typed)); err == nil {
				return parsed
			}
		}
	}
	return 0
}

func rawHash(hash string, jsonPath string) string {
	if jsonPath == "" {
		return hash
	}
	return hash + jsonPath
}
