# NEBULA navigation for cPanel & WHM

Version: **0.1.3-dev — prepared locally; not installed on a cPanel host.**

The [NEBULA panel](https://nebula.parallax.link) is live. This optional package adds a NEBULA entry in WHM and Jupiter. Each entry opens the configured portal in a new tab, where NEXUS sign-in and NEBULA determine the caller's organization access and platform role.

This version is navigation only. It does not connect an account, provision a cluster, join a node, embed a dashboard, transfer a cPanel session, or infer an organization from a hosting username or email. It sends no hosting-account identifiers, WHM tokens or Kubernetes credentials. It installs no system packages and changes no existing customer's hosting package. The vendor registration helpers have shared-cache, service-reload and notification effects described below.

## Before a host installation

The portal origin is `https://nebula.parallax.link`. A review of the exact target cPanel vendor helpers and their implementation modules is still required. Preparing this package authorizes neither a host installation nor its registration notification.

Official documentation establishes the registration interfaces but not every version-specific generated icon, Feature Manager or cache path. The installer therefore requires a **root-owned 0600 reviewed host profile**. It pins the five helper entry points, up to 32 reviewed public vendor source files, exact existing vendor-directory ownership/modes, and the exact own registration outputs with their hashes and modes. `vendor_sources` must include `Cpanel/AppConfig/Register.pm`, `Cpanel/Plugin/Install.pm` and `Cpanel/Themes/Serializer/DynamicUI.pm` beneath `/usr/local/cpanel/`; `registration_notification` must be `true`. See `profiles/reviewed-host-profile.schema.json`.

A host profile for Iota's inspected cPanel build `11.110.0.154` can be prepared separately. No real-host profile is bundled, and the offline fixture profile must never be used on a host.

The reviewer must identify every persistent own `parallax_nebula` registration output and the helpers' shared-cache, task, service and notification behavior. Unexpected effects require a source review/update; do not weaken the profile or guess a filename. Existing helper symlinks and unsupported ownership/layouts are refused. No vendor source or private host configuration is bundled.

Profile schema 2 requires exact `vendor_parents` UID0/GID/mode pins for existing directories beneath `/usr/local/cpanel`. These directories must be canonical and have no group or other write bits. This supports Iota’s existing protected root-owned0711 cPanel directory without changing it. Missing pins, ownership/mode drift, writable directories and symlinks are refused. The exception cannot cover the plugin’s own directories; portal/configuration and own targets retain their exact root:root ownership and modes.

Requirements already present on the host:

- cPanel & WHM with the Jupiter theme and its documented registration helpers.
- Existing cPanel Perl and its core modules; the installer requires no Python or added host package.
- A real `nobody` OS account with UID greater than zero. WHM CGI execution is explicitly `user=nobody`, never the default root identity.
- Existing cPanel LivePHP support. The PHP page requires PHP 8.0+ and no additional extension.
- Root-owned safe parent directories. The public portal configuration and every ancestor of that configuration must be root:root 0755 directories, except canonical `/` alone may be root:root 0555; the configuration itself must be a real root-owned 0644 file.

The WHM entry uses the existing `list-accts` ACL. It is available to root and resellers that already possess that privilege; the installer grants no ACL. Jupiter registers `featuremanager:1` under the existing Software group. Administrators may make the feature available through their normal Feature Manager workflow; installation does not change customer packages automatically. Neither panel permission grants any NEBULA platform role.

## Review and commands

Verify the public archive checksum before extraction. Extract the reviewed package as root into a root-owned directory whose ancestors are not group/world writable. Run commands with the existing cPanel Perl:

```sh
/usr/local/cpanel/3rdparty/bin/perl bin/nebula-cpanel --plan \
  --portal-url https://nebula.parallax.link

/usr/local/cpanel/3rdparty/bin/perl bin/nebula-cpanel --check \
  --portal-url https://nebula.parallax.link \
  --profile /root/reviewed-nebula-cpanel-host.json
```

The required value is a canonical lowercase HTTPS DNS origin. Credentials, IP address forms, paths, queries, fragments, whitespace and control characters are rejected. An explicit port 443 is normalized away; other ports are rejected. Navigation opens exactly this configured origin, where the primary panel can redirect to its dashboard/sign-in flow.

`--plan` without a profile returns `review-required` and writes nothing. `--check` returns success only when all represented prerequisites and exact own targets pass; it does not certify undocumented vendor side effects. Both modes invoke no mutating vendor helper.

Only after the host-specific review and a separate installation authorization:

```sh
/usr/local/cpanel/3rdparty/bin/perl bin/nebula-cpanel --install \
  --portal-url https://nebula.parallax.link \
  --profile /root/reviewed-nebula-cpanel-host.json \
  --acknowledge-registration-notification

/usr/local/cpanel/3rdparty/bin/perl bin/nebula-cpanel --uninstall \
  --profile /root/reviewed-nebula-cpanel-host.json
```

New AppConfig registration invokes cPanel's administrative notification. `--install` requires `--acknowledge-registration-notification`; that flag records awareness of the vendor behavior, not permission to send a message. Explicit authorization for the installation and notification is required before running it. This package has no notification-suppression or acknowledgement-bypass option.

The production CLI has no alternative host-root or helper-path override. The in-process fixture root is restricted to fresh local `/run/nebula-cpanel-test-*` test directories and is not a CLI option.

## Files and failure behavior

Application-owned namespaces:

- `/etc/parallax/nebula-cpanel/portal.json`: nonsecret `{schema_version:1, portal_url:...}` configuration.
- `/usr/local/cpanel/whostmgr/docroot/cgi/parallax-nebula/`: WHM landing CGI.
- `/usr/local/cpanel/base/frontend/jupiter/parallax-nebula/`: LivePHP landing page.
- `/usr/local/cpanel/3rdparty/parallax-nebula/`: exact registration inputs and original SVG icon.
- `/var/lib/parallax-nebula-cpanel/`: root 0700 operation state, root 0600 manifest and receipts.
- `/var/cpanel/apps/parallax_nebula.conf`: AppConfig-owned registration output, via its helper.
- `/usr/local/cpanel/base/frontend/jupiter/assets/application_icons/parallax_nebula.svg`: the own application icon, via the Jupiter helper.
- `/usr/local/cpanel/whostmgr/addonfeatures/parallax_nebula`: the own Feature Manager entry, via the Jupiter helper.

Own Jupiter outputs must be listed explicitly in the profile using the `parallax_nebula` filename namespace. Outside that tree, the cPanel output allowlist admits only the exact addon-feature path above. The installer does not edit `dynamicui.conf` or any vendor source directly. It calls AppConfig and Jupiter helpers separately, with argument lists and an explicit `--theme=jupiter`.

All targets must be absent before a new installation. An exact unchanged installation is idempotent; upgrades and portal changes are not silently applied. Uninstall verifies the manifest's file set, expected package bytes, inode/owner/mode identities, own-directory inventories and registration records before unregistering anything. It never recursively deletes a directory or follows a symlink.

A failed registration is rolled back only when source and known registration identities still match. Unknown content, identical-content inode replacements, concurrent edits or unrecognized helper side effects stop automatic recovery. A private receipt reports `manual-recovery`; no foreign file is removed. Preserve that receipt for review rather than repeatedly invoking vendor helpers. Uninstall failures can leave a partial own registration, so an unchanged-state assertion must not be mistaken for an uninstall retry instruction.

The installer bounds only its own helper child process, handles closed output pipes and ignored TERM, and refuses to signal a PID that is no longer its child. Vendor helpers separately rebuild menus, sprites and API data from the current registry. These shared caches are not owned package outputs: no directory-wide allowlist or blanket cache snapshot is used or restored. The review must check for an existing menu entry with the same display-name key.

AppConfig sends HUP to cpsrvd to reload its configuration. If that fails, the vendor can schedule `startcpsrvd`; registration cannot be described as strictly reload-only. Queued vendor work and a delivered administrative notification are not undone by removing the own entry. The package does not provision or alter Kubernetes workloads.

## Local verification and distribution

Run the meaningful fixtures as Linux root. They create only fresh root-owned local `/run/nebula-cpanel-test-*` trees with fake portal configuration, unprivileged render processes and stub vendor helpers. They never connect to a cPanel host.

```sh
prove t/installer.t t/renderers.t t/package.t
perl -c bin/nebula-cpanel
perl -c payload/whm/index.cgi
php -l payload/cpanel/index.live.php
sh scripts/package.sh
```

The original `dist/nebula-cpanel-0.1.0-dev.tar.gz` and the complete `dist/0.1.1-dev/` and `dist/0.1.2-dev/` artifacts are preserved. The new development tarball and public checksum are written under `dist/0.1.3-dev/`. Its internal `SOURCE-SHA256SUMS` binds the included source. Packaging requires ordinary local `tar`, `gzip` and `sha256sum`; those are build tools, not new host installation requirements.

The offline fixtures test neither live cPanel registration, WHM menu rendering nor Jupiter Feature Manager integration. The live NEBULA portal is separate from those fixtures; they do not verify its availability or NEXUS account sign-in. Host testing remains necessary after the target's vendor-helper effects are reviewed and installation is authorized.

No new project license is selected by this package. The SVG is original code-native Parallax artwork. No cPanel software or third-party icon is redistributed.

## Official integration references

- [WHM AppConfig registration](https://api.docs.cpanel.net/guides/guide-to-whm-plugins/guide-to-whm-plugins-appconfig-registration)
- [WHM AppConfig fields](https://api.docs.cpanel.net/guides/guide-to-whm-plugins/guide-to-whm-plugins-appconfig-configuration-file)
- [WHM ACL reference](https://api.docs.cpanel.net/guides/guide-to-whm-plugins/guide-to-whm-plugins-acl-reference-chart)
- [Jupiter install.json and Feature Manager](https://api.docs.cpanel.net/guides/guide-to-cpanel-plugins/guide-to-cpanel-plugins-add-plugins)
- [install_plugin](https://docs.cpanel.net/whm/scripts/the-install_plugin-script/)
- [uninstall_plugin](https://api.docs.cpanel.net/guides/guide-to-cpanel-plugins/guide-to-cpanel-plugins-uninstall-plugins)
- [unregister_appconfig](https://support.cpanel.net/hc/en-us/articles/4404719130263-How-do-I-use-unregister-appconfig)
