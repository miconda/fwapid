# FWAPID - FireWall API Daemon #

Simple REST API server to control an `iptables` firewall, with the option to
auto-delete the rules.

The scope is to be able to open ports for specific IPs with HTTP REST queries
on a restrictive firewall, but it can be also configured to block IPs on a
permissive firewall.

**Table Of Content**

  * [Install](#install)
    + [Compile From Sources](#compile-from-sources)
    + [Download Binary Release](#download-binary-release)
  * [Usage](#usage)
    + [Configuration File](#configuration-file)
    + [REST API URLs](#rest-api-urls)
    + [Systemd Service](#systemd-service)
    + [Log File](#log-file)
  * [License](#license)
  * [Contributions](#contributions)

## Install ##

### Compile From Sources ###

First install [Go](http://golang.org). Once the Go environment is configured, clone `fwapid` git repository:

```
git clone https://github.com/miconda/fwapid
```

Download dependencies and build:

```
cd fwapid
go get ./...
go build .
```

The binary `fwapid` should be generated in the current directory.

### Download Binary Release ###

Binary releases for `Linux`, `MacOS` and `Windows` are available at:

  * https://github.com/miconda/fwapid/releases

## Usage ##

Prototype:

```
fwapid [options] [target]
```

See `fwapid -h` for the command line options and arguments.

Example:

  * start `fwapid` using the config file `/etc/fwapid/fwapi-allow.json`, listening for HTTPS requests
  on `1.2.3.4:20443`, using the `Let's Encrypt` certificates for domain `server.com`, setting the rules
  cache expiration to `7200` seconds, with a cleanup timer interval of `60` seconds.

```
fwapid --config-file /etc/fwapid/fwapi-allow.json --https-srv 1.2.3.4:20443 --use-letsencrypt \
    --domain server.com --cache-expire 7200 --timer-interval 60
```

### Configuration File ###

The runtime attributes and policy rules are loaded from a JSON file that has to be specified
via `--config-file` cli parameter.

Example:

```json
{
	"mode": 1,
	"command": "iptables",
	"opadd": "-I",
	"opdel": "-D",
	"policy": "ACCEPT",
	"rules": [
		{
			"name": "admin",
			"key": "3FA6B8B3-1470-44B3-959B-202A8642D978",
			"dports": "80,443",
			"actions": ["allow", "allowip", "revoke", "revokeip", "show"]
		},
		{
			"name": "test",
			"key": "3FA6B8B3-1470-44B3-959B-202A8642D972",
			"dports": "80,443",
			"actions": ["allow", "show"]
		}
	]
}
```

The JSON fields are:

  * `mode` - reserved (not in used yet)
  * `command` - the iptables binary to execute (can be full path). If is not
  set, then its default value is `iptables`
  * `opadd` - option for adding the rule (default is `-I`)
  * `opdel` - option for deleting (removing) the rule (default is `-D`)
  * `policy` - what is the policy for firewall rules managed via `fwapid` (default
  is `ACCEPT`, it can be any valid `iptables` policy, e.g.,: `DROP`, `REJECT`)
  * `rules` - array with the rules for using `fwapid`:
    * `name` - name of the rule
	* `key` - the API key for executing the rule
	* `dports` - the list of ports to open/block with the rule
	* `actions` - array with the actions allowed for this rule
	  * `allow` - add `iptables` rule to allow traffic from source ip to the
	  ports in `dports`
	  * `allowip` - add `iptables` rule to allow traffic from specified ip to the
	  ports in `dports`
	  * `revoke` - delete `iptables` rule to allow traffic from source ip to the
	  ports in `dports`
	  * `revokeip` - delete `iptables` rule to allow traffic from specified ip to the
	  ports in `dports`
	  * `show` - return in HTTP response body the value of the source IP

The commands are performed for the `iptables` chain `INPUT`.

#### Key Generation ####

The key is sent as part of the URL, therefore use the application only via HTTPS secure connection
or over trusted networks (e.g., VPN, local host for testing and debugging).

When allocating a key, ensure that is unique and hard to predict (e.g., random). There is no constraint
from the code point of view, the value of the key can be any string that is valid to be uased as a token
in the URL path, therefore it must not contain `/`.

Among the options to generate the key:

* using UUID tools to generate Universally Unique Identifiers:

```
❯ uuid
4f3b12f2-c75d-11ef-8a39-637a95f243c7

❯ uuidgen
64954059-CB62-473C-8CD9-7EA8848A559C
```

* using `openssl` random generator

```
❯ openssl rand -hex 24
d77ff2d697f431ebbe24af99ca05303fd0307af7764f47f1
```

### REST API URLs ###

Trigger `add` action:

```
https://server.com:20443/allow/$KEY
```

Example:

```
curl https://server.com:20443/add/3FA6B8B3-1470-44B3-959B-202A8642D972
```

Aliases for `add` action: `addip`, `allow`, `allowip`.

Example:

```
https://server.com:20443/allowip/$KEY/$IP
```

```
curl https://server.com:20443/allowip/3FA6B8B3-1470-44B3-959B-202A8642D972/2.4.6.8
```

Trigger `remove` action:

```
https://server.com:20443/remove/$KEY
```

Example:

```
curl https://server.com:20443/remove/3FA6B8B3-1470-44B3-959B-202A8642D972
```

Aliases for `remove` action: `removeip`, `revoke`, `revokeip`.

Example:

```
https://server.com:20443/revokeip/$KEY/$IP
```

```
curl https://server.com:20443/revokeip/3FA6B8B3-1470-44B3-959B-202A8642D972/2.4.6.8
```

Trigger `show` action:

```
https://server.com:20443/show/$KEY
```

Example:

```
curl https://server.com:20443/show/3FA6B8B3-1470-44B3-959B-202A8642D972
```

### Systemd Service ###

To run `fwapid` as a `systemd` service, a unit file `/etc/systemd/system/fwapid.service`
can be created with a content like:

```
[Unit]
Description=fwapid

[Service]
Type=simple
Restart=always
RestartSec=5s
ExecStart=/usr/local/bin/fwapid --config-file /etc/fwapid/fwapi-allow.json --log-file /var/log/fwapid.log --https-srv 1.2.3.4:20443 --use-letsencrypt --domain server.com --cache-expire 7200 --timer-interval 60

[Install]
WantedBy=multi-user.target
```

### Log File ###

The `fwapid` service can write to a log file if specified by `--log-file` cli parameter,
otherwise will print the log messages to `stdout`.

When writing to a log file, it is recommended to configure `logrotate` for it.
The file `/etc/logrotate.d/fwapid` can be created with a content like:

```
/var/log/fwapid.log {
        daily
        missingok
        rotate 14
        compress
        delaycompress
        create 0644 root adm
        postrotate
                /usr/lib/rsyslog/rsyslog-rotate
        endscript
}
```

If `syslogd` is used instead of `rsyslogd`, the `postrotate` script should be
replaced with:

```
/bin/kill -HUP `cat /var/run/syslogd.pid 2> /dev/null` 2> /dev/null || true
```

## License ##

`GPLv3`

Copyright: `Daniel-Constantin Mierla` ([Asipto](https://www.asipto.com))

## Contributions ##

Contributions are welcome!

Fork and do pull requests:

  * https://github.com/miconda/fwapid
