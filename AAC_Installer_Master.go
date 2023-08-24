package main

/*
ADDITIONS TO DO:
Y MOVE SQL BACKUPS FOLDER
N CHECK EXTRACT CONTENTS
N PACKAGE INSIDE ADVANCED INSTALLER
GET SILENT INSTALLS AND RUN THEM INSIDE A NEW FUNCTION
func silentInstall (){
	postman
	erlang
	notepad ++
	C/C++ RUNTIME

}
Other installs such as Microsoft SQL and studio must be done manually.
GO LANG
AAC INSTALLER SOURCE CODE
TO BE PACKAGED INSIDE OF ADVANCED INSTALLER
         ____
        / _\ \
      .`\/  \ \
    ,`   \   \ \
     / /-`    \ \ .
    / /       ,\ `|
   / /        `-._|
  / /_.`|________\_\
  \/_<  ___________/
GO-   `.|
// The author of this code is not affiliated with, endorsed by, or associated with Microsoft or any of its subsidiaries or affiliates.
//DATE          : 23/08/2023
//AUTHOR        : ANTHONY GRACE
//COMPANY       : AAC SOLUTIONS PTY LTD
//DEPARTMENT    : IT TECHNICIAN
//COMP / VERSION: BETA-0.0.2
// PRG: AAC INSTALLER
// PUR: Install and automate the server setup checklist.
*/
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"time"

	_ "github.com/denisenkom/go-mssqldb"
)

func pullconfig() Config {
	configFile := "goconfig.json"
	var config Config
	file, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Failed to read config file %s: %v", configFile, err)
	}
	if err := json.Unmarshal(file, &config); err != nil {
		log.Fatalf("Failed to unmarshal JSON: %v", err)
	}
	return config
}

type Config struct {
	AuthToken      string `json:"authtoken"`   //abcdefghijklmopqrstuvwxyz
	Label          string `json:"label"`       //edge_edgheight
	Protocol       string `json:"protocol"`    //https
	Port           int    `json:"port"`        //80
	RegistryKey    string `json:"registryKey"` // 123456
	Server         string `json:"server"`      //DESKTOP-xxxxx ???
	User           string `json:"user"`        //pulselive
	Password       string `json:"password"`    //C:pulselive xxxx ??
	Database       string `json:"database"`    //C:/localhost?
	BackupFilePath string `json:"backupfilepath"`
}

var csr = "cert.csr"
var key = "cert.key"

func buildPowerShellScript(lines ...string) string {
	return strings.Join(lines, "; ")
}

func runPowerShellCommand(command string) error {
	cmd := exec.Command("powershell", "-command", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Failed to execute command: %s\nError: %v\n%s\n", command, err, out)
		return err
	}
	return nil
}

func silentInstall() {
	// URLs for downloading the installers
	installers := map[string]string{
		"postman":   "URL_TO_POSTMAN_INSTALLER", // Make sure to replace with the correct URLs
		"erlang":    "URL_TO_ERLANG_INSTALLER",
		"notepad++": "URL_TO_NOTEPAD++_INSTALLER",
		"C/C++":     "URL_TO_C_CPP_RUNTIME_INSTALLER",
	}

	for name, url := range installers {
		fmt.Printf("Downloading %s...\n", name)
		output := name + "_installer.exe"

		// PowerShell script to download the file and display progress with percentage
		downloadScript := buildPowerShellScript(
			fmt.Sprintf(`$url = "%s"; $output = "%s"`, url, output),
			"$wc = New-Object System.Net.WebClient",
			"$wc.DownloadProgressChanged += { Write-Progress -PercentComplete $_.ProgressPercentage -Status ('Downloading... ' + $_.ProgressPercentage + '%') }",
			"$wc.DownloadFileAsync($url, $output)",
			"while ($wc.IsBusy) { Start-Sleep -Milliseconds 100 }",
		)

		runPowerShellCommand(downloadScript)

		fmt.Printf("Installing %s...\n", name)
		installCommand := ""

		switch name {
		case "postman": // Assuming it's an MSI package
			installCommand = fmt.Sprintf(`Msiexec /i "%s" /qb! /l*v install.log`, output)
		case "erlang": // Assuming it's an MSI package
			installCommand = fmt.Sprintf(`Msiexec /i "%s" /qb! /l*v install.log`, output)
		case "notepad++": // Assuming it's an EXE file
			installCommand = output + " /S" // You might need to change this based on the specific silent install command for Notepad++
		case "C/C++": // Assuming it's an EXE file
			installCommand = output + " /S" // You might need to change this based on the specific silent install command for C/C++ Runtime
		}

		runPowerShellCommand(installCommand)
		fmt.Printf("%s installed successfully\n", name)
	}
}

func copySQLBackups(config Config) {
	command := fmt.Sprintf(`Copy-Item -Path .\SQLBACKUPS -Destination '%s' -Recurse -Force`, config.BackupFilePath)
	if err := runPowerShellCommand(command); err != nil {
		fmt.Printf("Failed to copy SQLBACKUPS directory to %s\nError: %v\n", config.BackupFilePath, err)
	} else {
		fmt.Printf("SQLBACKUPS directory copied successfully to %s\n", config.BackupFilePath)
	}
}

func backupDatabase(config Config) error {
	connString := fmt.Sprintf("server=%s;user id=%s;password=%s;database=%s;", config.Server, config.User, config.Password, config.Database)
	db, err := sql.Open("sqlserver", connString)
	if err != nil {
		return err
	}
	defer db.Close()

	query := `
	BACKUP DATABASE ? TO DISK = ?
	WITH STATS = 10
	`
	_, err = db.Exec(query, config.Database, config.BackupFilePath)
	if err != nil {
		return err
	}

	fmt.Printf("Database %s backed up successfully to %s\n", config.Database, config.BackupFilePath)
	return nil
}

func powershellList(config Config) {

	fmt.Println("COPYING PULSE LIVE PATCH: ")
	runPowerShellCommand(`Copy-Item -Path .\PATCH\Server\* -Destination 'C:\program files\pulselive' -Recurse -Force`)
	runPowerShellCommand(`Copy-Item -Path .\PATCH\Max\* -Destination 'C:\program files\pulselive\max' -Recurse -Force`)
	runPowerShellCommand(`Expand-Archive -Path .\PATCH\Client.zip -DestinationPath 'c:\inetpub\wwwroot\pulselive' -Force`)
	time.Sleep(1 * time.Second)

	fmt.Println("PERFORMING IIS CONFIGURATION: ")
	runPowerShellCommand(`Import-Module WebAdministration`)
	runPowerShellCommand(`Set-ItemProperty -Path 'IIS:\AppPools\DefaultAppPool' -Name Recycling.periodicRestart.schedule -Value @{value='06:00:00','09:00:00'}`)
	runPowerShellCommand(`New-WebApplication -Name "PulseLive" -Site "Default Web Site" -PhysicalPath 'c:\inetpub\wwwroot\pulselive' -ApplicationPool "DefaultAppPool"`)
	time.Sleep(1 * time.Second)

	fmt.Println("CONFIGURING REGISTRY: ")
	runPowerShellCommand(`New-Item -Path 'HKLM:\Software\AAC\L' -Force`)
	runPowerShellCommand(fmt.Sprintf(`New-ItemProperty -Path 'HKLM:\Software\AAC\L' -Name 'K' -Value '%s' -PropertyType 'String' -Force`, config.RegistryKey))
	time.Sleep(1 * time.Second)

	fmt.Println("APPLYING PULSELIVE LICENSE: ")
	runPowerShellCommand(`Copy-Item -Path .\pulselive.lic -Destination 'c:\program files\pulselive' -Force`)
	time.Sleep(1 * time.Second)

	fmt.Println("ADJUSTING POWER SETTINGS: ")
	runPowerShellCommand(`powercfg /change -standby-timeout-ac 0`)
	time.Sleep(1 * time.Second)

	fmt.Println("CHANGING FOLDER PERMS: ")
	runPowerShellCommand(`$acl = Get-Acl 'c:\inetpub\wwwroot\pulselive\CreatedReports'; $permission = 'IIS_IUSRS','FullControl','Allow'; $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission; $acl.SetAccessRule($accessRule); $acl | Set-Acl 'c:\inetpub\wwwroot\pulselive\CreatedReports'`)
	runPowerShellCommand(`$acl = Get-Acl 'c:\inetpub\wwwroot\pulselive\Logs'; $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission; $acl.SetAccessRule($accessRule); $acl | Set-Acl 'c:\inetpub\wwwroot\pulselive\Logs'`)
}

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
	log.Println("save", csr)
	os.WriteFile(csr, ca_b, 0644)
	log.Println("save", key)
	os.WriteFile(key, x509.MarshalPKCS1PrivateKey(priv), 0644)
}

func InstallAndConfigureNgrok(config Config) {

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

func main() {
	csrFile, err := os.ReadFile(csr)
	if err != nil {
		log.Println("Error reading csr file:", err)
	} else {
		log.Println("csr file found.")
	}
	keyFile, err := os.ReadFile(key)
	if err != nil {
		log.Println("Error reading key file:", err)
	} else {
		log.Println("key file found.")
	}
	if csrFile == nil && keyFile == nil {
		log.Println("No certs found, generating new self-signed certs.")
		genCert()
	}
	config := pullconfig()
	backupDatabase(config)
	silentInstall()
	copySQLBackups(config)
	powershellList(config)
	InstallAndConfigureNgrok(config)
}
