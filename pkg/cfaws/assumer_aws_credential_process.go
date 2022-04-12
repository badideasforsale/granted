package cfaws

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/processcreds"
	"github.com/bigkevmcd/go-configparser"
	"github.com/urfave/cli/v2"
)

// Implements Assumer using the aws credential_process standard
type CredentialProcessAssumer struct {
}

func (cpa *CredentialProcessAssumer) AssumeTerminal(c *cli.Context, cfg *CFSharedConfig, args2 []string) (creds aws.Credentials, region string, err error) {
	var credProcessCommand string
	for k, v := range cfg.RawConfig {
		if k == "credential_process" {
			credProcessCommand = v
			break
		}
	}
	p := processcreds.NewProvider(credProcessCommand)
	region, _, err = cfg.Region(c.Context)
	if err != nil {
		return
	}
	creds, err = p.Retrieve(c.Context)
	return creds, region, err

}

func (cpa *CredentialProcessAssumer) AssumeConsole(c *cli.Context, cfg *CFSharedConfig, args []string) (creds aws.Credentials, region string, err error) {
	return cpa.AssumeTerminal(c, cfg, args)
}

// A unique key which identifies this assumer e.g AWS-SSO or GOOGLE-AWS-AUTH
func (cpa *CredentialProcessAssumer) Type() string {
	return "AWS_CREDENTIAL_PROCESS"
}

// inspect for any credential processes with the saml2aws tool
func (cpa *CredentialProcessAssumer) ProfileMatchesType(rawProfile configparser.Dict, parsedProfile config.SharedConfig) bool {
	for k := range rawProfile {
		if k == "credential_process" {
			return true
		}
	}
	return false
}
