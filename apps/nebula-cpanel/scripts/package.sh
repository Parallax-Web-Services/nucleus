#!/bin/sh
set -eu
umask 077
package_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
version=0.1.3-dev
archive="nebula-cpanel-$version.tar.gz"
distribution_dir="$package_dir/dist/$version"
set -- README.md bin/nebula-cpanel lib/Parallax/NebulaCPanel/Installer.pm payload/whm/index.cgi payload/whm/parallax_nebula.conf payload/cpanel/index.live.php payload/shared/nebula.svg payload/registration/install.json profiles/reviewed-host-profile.schema.json scripts/package.sh t/installer.t t/renderers.t t/package.t
for file do
    test -f "$package_dir/$file" && test ! -L "$package_dir/$file" || { echo "Missing or linked package source: $file" >&2; exit 1; }
done
test -d "$package_dir/dist" && test ! -L "$package_dir/dist" || { echo 'Real local dist directory required' >&2; exit 1; }
if test ! -e "$distribution_dir" && test ! -L "$distribution_dir"; then mkdir -- "$distribution_dir"; fi
test -d "$distribution_dir" && test ! -L "$distribution_dir" || { echo 'Real versioned distribution directory required' >&2; exit 1; }
if test -e "$distribution_dir/$archive" || test -L "$distribution_dir/$archive" || test -e "$distribution_dir/SHA256SUMS" || test -L "$distribution_dir/SHA256SUMS"; then
    echo 'Existing distribution output refused; preserve it and choose a reviewed new version.' >&2
    exit 1
fi
stage=$(mktemp -d "$distribution_dir/.package-XXXXXXXX")
cleanup() { rm -f -- "$stage/archive" "$stage/package.tar" "$stage/SOURCE-SHA256SUMS" "$stage/SHA256SUMS"; rmdir -- "$stage"; }
trap cleanup EXIT HUP INT TERM
(cd "$package_dir" && sha256sum "$@") > "$stage/SOURCE-SHA256SUMS"
tar --sort=name --format=ustar --mtime=@0 --owner=0 --group=0 --numeric-owner --transform "s,^,nebula-cpanel-$version/," -C "$package_dir" -cf "$stage/package.tar" "$@" -C "$stage" SOURCE-SHA256SUMS
gzip -n -c "$stage/package.tar" > "$stage/archive"
(cd "$package_dir" && sha256sum -c "$stage/SOURCE-SHA256SUMS") >/dev/null
hash=$(sha256sum "$stage/archive")
hash=${hash%% *}
printf '%s  %s\n' "$hash" "$archive" > "$stage/SHA256SUMS"
chmod 0644 "$stage/archive" "$stage/SHA256SUMS"
ln -- "$stage/archive" "$distribution_dir/$archive"
ln -- "$stage/SHA256SUMS" "$distribution_dir/SHA256SUMS"
printf '%s  %s\n' "$hash" "$distribution_dir/$archive"
