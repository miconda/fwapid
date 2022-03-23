# FWAPID - FireWall API Daemon #

Simple REST API server to control an `iptables` firewall, with the option to
auto-delete the rules.

The scope is to be able to open ports for specific IPs with HTTP REST queries
on a restrictive firewall, but it can be also configured to block IPs on a
permissive firewall.

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
fwapid --allow-file /etc/fwapid/fwapi-allow.json --https-srv 1.2.3.4:20443 --use-letsencrypt \
    --domain server.com --cache-expire 7200 --timer-interval 60
```

### Configuration File ###

The runtime attributes and policy rules are loaded from a JSON file that has to be specified
via `--allow-file` cli parameter.

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
  * `opdel` - option for deleting the rule (default is `-D`)
  * `policy` - what is the policy for firewall rules managed via `fwapid` (default
  is `ACCEPT`)
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

### REST API URLs ###

Trigger `allow` action:

```
https://server.com:20443/allow/$KEY
```

Example:

```
curl https://server.com:20443/allow/3FA6B8B3-1470-44B3-959B-202A8642D972
```

Trigger `allowip` action:

```
https://server.com:20443/allowip/$KEY/$IP
```

Example:

```
curl https://server.com:20443/allowip/3FA6B8B3-1470-44B3-959B-202A8642D972/2.4.6.8
```

Trigger `revoke` action:

```
https://server.com:20443/revoke/$KEY
```

Example:

```
curl https://server.com:20443/revoke/3FA6B8B3-1470-44B3-959B-202A8642D972
```

Trigger `revokeip` action:

```
https://server.com:20443/revokeip/$KEY/$IP
```

Example:

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

## License ##

`GPLv3`

Copyright: `Daniel-Constantin Mierla` ([Asipto](https://www.asipto.com))

## Contributions ##

Contributions are welcome!

Fork and do pull requests:

  * https://github.com/miconda/fwapid