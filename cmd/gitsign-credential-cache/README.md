# gitsign-credential-cache

`gitsign-credential-cache` is a **optional** helper binary that allows users to
cache signing credentials. This can be helpful in situations where you need to
perform multiple signing operations back to back.

Credentials are stored in memory, and the cache is exposed via a Unix socket.
Credentials stored in this cache are only as secure as the unix socket
implementation on your OS - any user that can access the socket can access the
data.

⚠️ When in doubt, we recommend **not** using the cache. In particular:

- If you're running on a shared system
  - if other admins have access to the cache socket they can access your keys.
- If you're running in an environment that has ambient OIDC credentials (e.g.
  GCE/GKE, AWS, GitHub Actions, etc.), Gitsign will automatically use the
  environment's OIDC credentials. You don't need caching.

If you understand the risks, read on!

## What's stored in the cache

- Ephemeral Private Key
- Fulcio Code Signing certificate + chain

All data is stored in memory, keyed by the configured Git email (`user.email`)
and signing configuration: OIDC issuer, client ID, connector, token provider,
Fulcio URL, and additional Fulcio root path. Repositories and worktrees with the
same settings share credentials, including worktrees created after login.
Different identities or signing configurations have separate entries.

The data that is cached would allow any user with access to sign artifacts as
you, until the signing certificate expires, typically in ten minutes.

## Usage

```sh
$ gitsign-credential-cache &
$ export GITSIGN_CREDENTIAL_CACHE="$HOME/.cache/sigstore/gitsign/cache.sock"
$ git commit ...
```

Note: The cache directory will change depending on your OS - the socket file
that is used is output by `gitsign-credential-cache` when it is spawned. See
[os.UserCacheDir](https://pkg.go.dev/os#UserCacheDir) for details on how the
cache directory is selected.

### Prime credentials at startup

Authenticate using one or more repositories' configurations before the daemon
starts accepting requests:

```sh
gitsign-credential-cache --prime ~/src/repo-a --prime ~/src/repo-b
```

Repeat `--prime` for each repository whose identity you need. Repositories with
identical identity settings authenticate only once. Relative repository paths
are resolved from the launch directory, and each repository's Git configuration
and the usual environment overrides are honored. An invalid repository or
failed login aborts startup.

Startup priming supports browser, device, and configured token-provider flows.
It never reads terminal input; browser failure cannot stop a background daemon
with `SIGTTIN`. For manual verification-code entry, authenticate through a
foreground signing command instead. Complete startup login before relying on
the cache socket. A service may use repeated `--prime /absolute/repo/path`
arguments if its environment can perform the configured login flow.

After certificates expire (typically ten minutes), the next signing command
authenticates in the foreground and replaces the shared cache entry. The daemon
never performs authentication in response to an RPC request. Cache RPCs time
out after five seconds, allowing the signer to fall back to foreground login.

Install both `gitsign` and `gitsign-credential-cache` from this fork to use the
shared identity keys. Existing upstream clients continue to use their old,
per-directory entries. Restart the daemon after upgrading; the cache is in memory.

### Systemd service

There are systemd user units in contrib

Change path to gitsign-credential-cache in service unit

```sh
${EDITOR:-vi} ./contrib/systemd/gitsign-credential-cache.service
```

Install units in home directory for specific user

```sh
install -m 0660 -D -t $HOME/.config/systemd/user/ ./contrib/systemd/gitsign-credential-cache.{socket,service}
systemctl --user daemon-reload
```

OR install them for all users

```sh
sudo install -m 0660 -D -t /etc/systemd/user/ ./contrib/systemd/gitsign-credential-cache.{socket,service}
sudo systemctl daemon-reload
```

After that you can enable and start socket service

```sh
systemctl --user enable --now gitsign-credential-cache.socket
```

### Forwarding cache over SSH

(Requires gitsign >= v0.5)

The credential cache socket can be forwarded over SSH using `RemoteForward`:

```sh
[local]  $ ssh -R /home/wlynch/.sigstore/cache.sock:${GITSIGN_CREDENTIAL_CACHE} <host>
[remote] $ export GITSIGN_CREDENTIAL_CACHE="/home/wlynch/.sigstore/cache.sock"
[remote] $ git commit ...
```

(format is `-R <remote path>:<local path>`)

or in `~/.ssh/config`:

```
Host amazon
    RemoteForward /home/wlynch/.cache/sigstore/cache.sock /Users/wlynch/Library/Caches/sigstore/gitsign/cache.sock
```

where `/home/wlynch/.cache/sigstore/cache.sock` is the location of the socket path on
the remote host (this can be changed, so long as the environment variable is
also updated to match).

#### Common issues

> Warning: remote port forwarding failed for listen path

- The socket directory must exist on the remote, else the socket will fail to
  mount.
- We recommend setting `StreamLocalBindUnlink yes` on the remote
  `/etc/ssh/sshd_config` to allow for sockets to be overwritten on the same path
  for new connections - SSH does not cleanup sockets automatically on exit and
  the socket forwarding will fail if a file already exists on the remote path
  (see [thread](https://marc.info/?l=openssh-unix-dev&m=151998074424424&w=2) for
  more discussion).


## Running it as a launchctl service on macOS

If you are a macOS user, you can run `gitsign-credential-cache` as a launchctl service using the following instructions:

Create the file `/tmp/gitsign-credential-cache.sh` with the following contents:

```sh
#!/bin/bash
set -euo pipefail

if ! command -v gitsign &> /dev/null; then
    echo "gitsign command not found. Please install it before running this script: https://docs.sigstore.dev/signing/gitsign/"
    exit 1
fi

if ! command -v gitsign-credential-cache &> /dev/null; then
    echo "gitsign-credential-cache command not found. Please install it before running this script: 'go install github.com/sigstore/gitsign/cmd/gitsign-credential-cache@latest'"
    exit 1
fi

launch_agents_dir="${HOME}/Library/LaunchAgents"
plist_name="my.gitsign-credential-cache.plist"
plist_path="${launch_agents_dir}/${plist_name}"
gitsign_cache_dir="${HOME}/Library/Caches/sigstore/gitsign"
gitsign_cache_path="${gitsign_cache_dir}/cache.sock"

if [ -f "${plist_path}" ]; then
    echo "The plist file ${plist_path} already exists. Please remove it or use a different name."
    exit 1
fi

if [ -f "${gitsign_cache_path}" ]; then
    echo "The gitsign cache path ${gitsign_cache_path} already exists. Please remove it or use a different name."
    exit 1
fi

mkdir -pv "${launch_agents_dir}"

# https://github.com/sigstore/gitsign/blob/main/cmd/gitsign-credential-cache/README.md
cat << EOF > "${plist_path}"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>KeepAlive</key>
    <true/>
    <key>Label</key>
    <string>my.gitsign-credential-cache</string>
    <key>ProgramArguments</key>
    <array>
            <string>/opt/homebrew/bin/gitsign-credential-cache</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/opt/homebrew/var/log/gitsign-credential-cache.log</string>
    <key>StandardOutPath</key>
    <string>/opt/homebrew/var/log/gitsign-credential-cache.log</string>
</dict>
</plist>
EOF

chmod 644 "${plist_path}"
chown $(whoami) "${plist_path}"

echo "Created plist file: ${plist_path}"

launchctl load -wF "${plist_path}"
plutil -lint "${plist_path}"

if [ ! -d "${gitsign_cache_dir}" ]; then
    echo "The gitsign cache directory ${gitsign_cache_dir} does not exist. Creating it now."
    mkdir -pv "${gitsign_cache_dir}"
fi

export GITSIGN_CREDENTIAL_CACHE="${gitsign_cache_path}"

if [ -f "${HOME}/.zshrc" ]; then
    shell_config_file="${HOME}/.zshrc"
elif [ -f "${HOME}/.bashrc" ]; then
    shell_config_file="${HOME}/.bashrc"
else
    echo "No .bashrc or .zshrc found in your home directory."
    exit 1
fi

export_line="export GITSIGN_CREDENTIAL_CACHE=\"${gitsign_cache_path}\""
if ! grep -qF -- "${export_line}" "${shell_config_file}"; then
    echo "${export_line}" >> "${shell_config_file}"
    echo "Added GITSIGN_CREDENTIAL_CACHE to ${shell_config_file}. Please restart your shell to apply the changes: 'source ${shell_config_file}'"
else
    echo "GITSIGN_CREDENTIAL_CACHE already exists in ${shell_config_file}!"
fi
```

Then run the following commands in your terminal:

```sh
chmod +x /tmp/gitsign-credential-cache.sh
echo "Running the script to create the launchctl service..."
/tmp/gitsign-credential-cache.sh
```

Once you did that now you should be able to see the `gitsign-credential-cache` service running by running the following command:

```sh
$ launchctl list | grep -i "my.gitsign"
2398    0       my.gitsign-credential-cache
```

and of course if you would like to tail the logs of your service you can do so by running the following command:

```sh
tail -f /opt/homebrew/var/log/gitsign-credential-cache.log
```
