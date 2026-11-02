// Package resourcemap embeds the local read-only Chromium interface.
package resourcemap

import "embed"

//go:embed index.html styles.css app.js
var Assets embed.FS
