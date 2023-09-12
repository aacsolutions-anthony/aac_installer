package main

// The author of this code is not affiliated with, endorsed by, or associated with Microsoft or any of its subsidiaries or affiliates.
//
//DATE          : 12/09/2023
//AUTHOR        : ANTHONY GRACE
//COMPANY       : AAC SOLUTIONS PTY LTD
//DEPARTMENT    : IT TECHNICIAN
//VERSION       : BETA-0.0.3
//
// PROGRAM: NGROK INSTALLER
// PURPOSE: Install and automate the ngrok installation process and setup checklist.

// Make improvements such as declaring a config package at global level that can be imported where necessary.
// Instead of configs current usage.
import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Config declares a type that will store your application's configurations.
type Config struct {
	AuthToken   string `json:"authtoken"`
	Label       string `json:"label"`
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
	RegistryKey string `json:"registryKey"`
}

// globalConfig is a global instance of Config, storing the actual configurations.
var globalConfig Config

// LoadConfig loads the config from goconfig.json.
func LoadConfig() {
	configFile := "goconfig.json"
	file, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Failed to read config file %s: %v", configFile, err)
	}

	if err := json.Unmarshal(file, &globalConfig); err != nil {
		log.Fatalf("Failed to unmarshal JSON: %v", err)
	}
}

// GetConfig returns the global config instance.
func GetConfig() *Config {
	return &globalConfig
}

func buildPowerShellScript(lines ...string) string {
	return strings.Join(lines, "; ")
}

func runPowerShellCommand(command string) {
	cmd := exec.Command("powershell", "-command", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Failed to execute command: %s\nError: %v\n%s\n", command, err, out)
	}
}

func powershellList(config Config) {

	fmt.Println("COPYING PULSE LIVE PATCH: \n")
	runPowerShellCommand(`Copy-Item -Path .\PATCH\Server\* -Destination 'C:\program files\pulselive' -Recurse -Force`)
	runPowerShellCommand(`Copy-Item -Path .\PATCH\Max\* -Destination 'C:\program files\pulselive\max' -Recurse -Force`)
	runPowerShellCommand(`Expand-Archive -Path .\PATCH\Client.zip -DestinationPath 'c:\inetpub\wwwroot\pulselive' -Force`)
	time.Sleep(1 * time.Second)
	fmt.Println("PERFORMING IIS CONFIGURATION: \n ")
	runPowerShellCommand(`Import-Module WebAdministration`)
	runPowerShellCommand(`Set-ItemProperty -Path 'IIS:\AppPools\DefaultAppPool' -Name Recycling.periodicRestart.schedule -Value @{value='06:00:00','09:00:00'}`)
	runPowerShellCommand(`New-WebApplication -Name "PulseLive" -Site "Default Web Site" -PhysicalPath 'c:\inetpub\wwwroot\pulselive' -ApplicationPool "DefaultAppPool"`)
	time.Sleep(1 * time.Second)
	fmt.Println("CONFIGURING REGISTRY: \n")
	runPowerShellCommand(`New-Item -Path 'HKLM:\Software\AAC\L' -Force`)
	runPowerShellCommand(fmt.Sprintf(`New-ItemProperty -Path 'HKLM:\Software\AAC\L' -Name 'K' -Value '%s' -PropertyType 'String' -Force`, config.RegistryKey))
	time.Sleep(1 * time.Second)
	fmt.Println("APPLYING PULSELIVE LICENSE: \n")
	runPowerShellCommand(`Copy-Item -Path .\pulselive.lic -Destination 'c:\program files\pulselive' -Force`)
	time.Sleep(1 * time.Second)
	fmt.Println("ADJUSTING POWER SETTINGS: \n")
	runPowerShellCommand(`powercfg /change -standby-timeout-ac 0`)
	time.Sleep(1 * time.Second)
	fmt.Println("CHANGING FOLDER PERMS: \n")
	runPowerShellCommand(`$acl = Get-Acl 'c:\inetpub\wwwroot\pulselive\CreatedReports'; $permission = 'IIS_IUSRS','FullControl','Allow'; $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission; $acl.SetAccessRule($accessRule); $acl | Set-Acl 'c:\inetpub\wwwroot\pulselive\CreatedReports'`)
	runPowerShellCommand(`$acl = Get-Acl 'c:\inetpub\wwwroot\pulselive\Logs'; $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission; $acl.SetAccessRule($accessRule); $acl | Set-Acl 'c:\inetpub\wwwroot\pulselive\Logs'`)
}

func verifyFileHash(filePath string, expectedHash string) bool {
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		log.Println("Failed to read file for hash verification: ", err)
		return false
	}
	hash := sha256.Sum(fileBytes)
	hashInString := hex.EncodeToString(hash[:])
	return hashInString == expectedHash
}

func InstallAndConfigureNgrok() {
	configFile := "goconfig.json"
	var config Config
	file, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Failed to read config file %s: %v", configFile, err)
	}
	if err := json.Unmarshal(file, &config); err != nil {
		log.Fatalf("Failed to unmarshal JSON: %v", err)
	}
	fmt.Printf("Welcome to the AAC Solutions installer to install and configure ngrok software.\n")
	time.Sleep(1 * time.Second)
	fmt.Printf("Current authtoken: %s\n", config.AuthToken)
	time.Sleep(1 * time.Second)
	fmt.Printf("Current label: %s\n", config.Label)
	time.Sleep(1 * time.Second)
	fmt.Printf("Current protocol: %s\n", config.Protocol)
	time.Sleep(1 * time.Second)
	fmt.Printf("Current port: %d\n", config.Port)
	time.Sleep(1 * time.Second)
	fmt.Print("Would you like to change these values? (yes/no): ")
	time.Sleep(1 * time.Second)

	var response string

	fmt.Scanln(&response)

	response = strings.ToLower(response)

	validResponses := []string{"yes", "y"}

	for _, validResponse := range validResponses {
		if response == validResponse {
			fmt.Print("Enter new authtoken: ")
			fmt.Scanln(&config.AuthToken)
			fmt.Print("Enter new label: ")
			fmt.Scanln(&config.Label)
			fmt.Print("Enter new protocol: ")
			fmt.Scanln(&config.Protocol)
			fmt.Print("Enter new port: ")
			fmt.Scanln(&config.Port)
			break
		}
	}
	ngrokPath := ".\\ngrok\\ngrok.exe"
	if _, err := os.Stat(ngrokPath); os.IsNotExist(err) {
		installScript := buildPowerShellScript(
			`$url = "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-windows-amd64.zip"; $output = "ngrok-v3-stable-windows-amd64.zip"`,
			"Invoke-WebRequest -Uri $url -OutFile $output",
			"Expand-Archive -Path $output -DestinationPath .\\ngrok",
			"Set-Location -Path .\\ngrok",
		)
		cmd := exec.Command("powershell", "-nologo", "-noprofile", "-command", installScript)
		_, err := cmd.CombinedOutput()
		if err != nil {
			log.Fatal(err)
		}
	}
	runScript := buildPowerShellScript(
		fmt.Sprintf(".\\ngrok.exe config add-authtoken %s", config.AuthToken),
		fmt.Sprintf(".\\ngrok.exe tunnel --label %s %s://localhost:%d", config.Label, config.Protocol, config.Port),
	)
	cmd := exec.Command("powershell", "-nologo", "-noprofile", "-command", runScript)
	cmd.Dir = ".\\ngrok"
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", out)
}

/*
	func genCert() {
	    ca := &x509.Certificate{
	        SerialNumber: big.NewInt(1337),
	        Subject: pkix.Name{
	            Country:            []string{"AU"},
	            Organization:       []string{"AAC Solutions Pty Ltd"},
	            OrganizationalUnit: []string{"IT"},
	        },
	        SignatureAlgorithm:    x509.SHA512WithRSA,
	        PublicKeyAlgorithm:    x509.ECDSA,
	        NotBefore:             time.Now(),
	        NotAfter:              time.Now().AddDate(0, 0, 10),
	        SubjectKeyId:          []byte{1, 2, 3, 4, 5},
	        BasicConstraintsValid: true,
	        IsCA:                  true,
	        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	        KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	    }
	    priv, _ := rsa.GenerateKey(rand.Reader, 4096)
	    pub := &priv.PublicKey
	    ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	    if err != nil {
	        log.Fatalf("create cert failed %#v", err)
	    }
	    log.Println("save", pem)
	    ioutil.WriteFile(pem, ca_b, 0644)
	    log.Println("save", key)
	    ioutil.WriteFile(key, x509.MarshalPKCS1PrivateKey(priv), 0644)
	}
*/
func main() {
	ngrokZipFile := "./ngrok-v3-stable-windows-amd64.zip"
	InstallAndConfigureNgrok()
	expectedHash := "1b60097bf1ccb15a952e5bcc3522cf5c162da68c381a76abc2d5985659e4d386"
	if !verifyFileHash(ngrokZipFile, expectedHash) {
		log.Println("Hash verification failed for ngrok zip file.")
	} else {
		log.Println("Hash verification passed for ngrok zip file.")
	}
}
