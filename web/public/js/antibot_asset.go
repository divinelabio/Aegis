package js

import _ "embed"

// AntibotSDK is compiled into the Aegis server so serving the public Bot SDK
// never depends on the process working directory containing web assets.
//
//go:embed antibot.js
var AntibotSDK []byte
