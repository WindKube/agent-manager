// No `replace` directive belongs in this file, ever. `go install
// github.com/WindKube/agent-manager/cli@latest` must resolve against the public
// repository, and a replace back to the hub module at the repo root makes that
// command fail for everyone outside this working tree.
module github.com/WindKube/agent-manager/cli

go 1.26.6

require (
	github.com/99designs/keyring v1.2.2
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.12.1
)

require (
	github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4 // indirect
	github.com/danieljoos/wincred v1.1.2 // indirect
	github.com/dvsekhvalnov/jose2go v1.5.0 // indirect
	github.com/godbus/dbus v0.0.0-20190726142602-4481cbc300e2 // indirect
	github.com/gsterjov/go-libsecret v0.0.0-20161001094733-a6f4afe4910c // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mtibben/percent v0.2.1 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sys v0.3.0 // indirect
	golang.org/x/term v0.3.0 // indirect
)
