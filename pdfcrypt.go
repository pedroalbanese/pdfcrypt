package main

import (
	"bufio"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/digitorus/pdfsign/sign"
	"github.com/digitorus/pdfsign/verify"
	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// loadPrivateKey loads an RSA private key from PEM file, requesting password if encrypted
func loadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}

	// Check if private key is encrypted
	if strings.Contains(block.Type, "ENCRYPTED") || x509.IsEncryptedPEMBlock(block) {
		fmt.Printf("Private key is encrypted.\n")
		password, err := askPassword("Enter private key password: ")
		if err != nil {
			return nil, fmt.Errorf("error reading password: %v", err)
		}

		// Try to decrypt PKCS8 key
		decryptedBlock, err := x509.DecryptPEMBlock(block, password)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %v", err)
		}

		// Try to parse as PKCS8
		key, err := x509.ParsePKCS8PrivateKey(decryptedBlock)
		if err != nil {
			// Try to parse as PKCS1
			key, err := x509.ParsePKCS1PrivateKey(decryptedBlock)
			if err != nil {
				return nil, fmt.Errorf("failed to parse decrypted private key: %v", err)
			}
			return key, nil
		}

		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("decrypted key is not an RSA key")
		}
		return rsaKey, nil
	}

	// Support both PKCS1 and PKCS8 for unencrypted keys
	if block.Type == "RSA PRIVATE KEY" {
		// PKCS1
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if block.Type == "PRIVATE KEY" {
		// PKCS8
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA key")
		}
		return rsaKey, nil
	}

	return nil, fmt.Errorf("invalid key type: %s", block.Type)
}

// askPassword prompts user for password using simple stdin
func askPassword(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	// Remove newline from the end
	password = strings.TrimSpace(password)
	return []byte(password), nil
}

// loadCertificate loads an x509 certificate
func loadCertificate(filename string) (*x509.Certificate, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid file type, expected CERTIFICATE, got: %s", block.Type)
	}

	return x509.ParseCertificate(block.Bytes)
}

// loadCRLFromFile loads a single CRL from PEM file
func loadCRLFromFile(crlFile string) (*x509.RevocationList, error) {
	data, err := os.ReadFile(crlFile)
	if err != nil {
		return nil, fmt.Errorf("error reading CRL file %s: %v", crlFile, err)
	}

	// Parse PEM format
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM from CRL file %s", crlFile)
	}

	if block.Type != "X509 CRL" && block.Type != "CRL" {
		return nil, fmt.Errorf("invalid PEM type in CRL file %s: expected X509 CRL or CRL, got %s", crlFile, block.Type)
	}

	// Parse CRL
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing CRL from file %s: %v", crlFile, err)
	}

	fmt.Printf("✓ Loaded CRL from: %s\n", crlFile)
	fmt.Printf("  Issuer: %s\n", crl.Issuer.String())
	fmt.Printf("  This Update: %s\n", crl.ThisUpdate.Format("2006-01-02 15:04:05"))
	if !crl.NextUpdate.IsZero() {
		fmt.Printf("  Next Update: %s\n", crl.NextUpdate.Format("2006-01-02 15:04:05"))
	}
	fmt.Printf("  Revoked Certificates: %d\n\n", len(crl.RevokedCertificates))

	return crl, nil
}

func addPassword(inputFile, outputFile, userPassword, ownerPassword string) error {
	conf := model.NewDefaultConfiguration()
	conf.UserPW = userPassword
	conf.OwnerPW = ownerPassword
	conf.EncryptUsingAES = true
	conf.EncryptKeyLength = 256

	return api.EncryptFile(inputFile, outputFile, conf)
}

func removePassword(inputFile, outputFile, userPassword, ownerPassword string) error {
	conf := model.NewDefaultConfiguration()
	conf.UserPW = userPassword
	conf.OwnerPW = ownerPassword

	return api.DecryptFile(inputFile, outputFile, conf)
}

func validatePDF(inputFile, userPassword, ownerPassword string) error {
	conf := model.NewDefaultConfiguration()

	// If passwords provided, configure for encrypted PDF validation
	if userPassword != "" || ownerPassword != "" {
		conf.UserPW = userPassword
		conf.OwnerPW = ownerPassword
		fmt.Printf("Validating encrypted PDF: %s\n", inputFile)
	} else {
		fmt.Printf("Validating PDF: %s\n", inputFile)
	}

	err := api.ValidateFile(inputFile, conf)
	if err != nil {
		return fmt.Errorf("PDF validation error: %v", err)
	}

	if userPassword != "" || ownerPassword != "" {
		fmt.Println("✓ Encrypted PDF validation completed successfully")
		fmt.Println("✓ Encrypted PDF is structurally correct")
		fmt.Println("✓ Passwords validated successfully")
	} else {
		fmt.Println("✓ Basic PDF validation completed successfully")
		fmt.Println("✓ PDF is structurally correct")
	}

	return nil
}

// signPDFWithTimestamp signs with timestamp
func signPDFWithTimestamp(inputFile, outputFile, privateKeyFile, certFile string) error {
	// Load private key
	privateKey, err := loadPrivateKey(privateKeyFile)
	if err != nil {
		return fmt.Errorf("error loading private key: %v", err)
	}

	// Load certificate
	certificate, err := loadCertificate(certFile)
	if err != nil {
		return fmt.Errorf("error loading certificate: %v", err)
	}

	fmt.Printf("Signing PDF with timestamp...\n")

	// Configuration with timestamp
	signData := sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        certificate.Subject.CommonName,
				Location:    "Location",
				Reason:      "Digitally signed document with timestamp",
				ContactInfo: "Digital signature",
				Date:        time.Now().Local(),
			},
			CertType:   sign.CertificationSignature,
			DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Signer:          privateKey,
		DigestAlgorithm: crypto.SHA256,
		Certificate:     certificate,
		TSA: sign.TSA{
			URL: "https://freetsa.org/tsr",
		},
	}

	err = sign.SignFile(inputFile, outputFile, signData)
	if err != nil {
		return fmt.Errorf("error signing PDF with timestamp: %v", err)
	}

	fmt.Printf("✓ PDF SIGNED WITH TIMESTAMP\n")
	fmt.Printf("✓ File: %s\n", outputFile)
	fmt.Printf("✓ Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("✓ TSA Server: https://freetsa.org/tsr\n")

	return nil
}

// validateSignatures validates signatures in PDF
func validateSignatures(inputFile string) error {
	fmt.Printf("Validating EMBEDDED signatures in: %s\n", inputFile)

	// Open PDF file
	file, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("error opening PDF file: %v", err)
	}
	defer file.Close()

	// Validate signatures
	response, err := verify.VerifyFile(file)
	if err != nil {
		return fmt.Errorf("error validating signatures: %v", err)
	}

	// Convert to JSON to show result
	jsonData, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return fmt.Errorf("error formatting response: %v", err)
	}

	fmt.Printf("Validation result:\n%s\n", string(jsonData))

	return nil
}

// validateSignaturesDetailed detailed validation with options
func validateSignaturesDetailed(inputFile string) error {
	fmt.Printf("Detailed signature validation in: %s\n", inputFile)

	file, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("error opening PDF file: %v", err)
	}
	defer file.Close()

	// Advanced validation options
	options := verify.DefaultVerifyOptions()
	options.EnableExternalRevocationCheck = true
	options.TrustSignatureTime = true
	options.ValidateTimestampCertificates = true
	options.HTTPTimeout = 15 * time.Second

	response, err := verify.VerifyFileWithOptions(file, options)
	if err != nil {
		return fmt.Errorf("error in detailed validation: %v", err)
	}

	// Convert to JSON
	jsonData, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return fmt.Errorf("error formatting response: %v", err)
	}

	fmt.Printf("Detailed validation result:\n%s\n", string(jsonData))

	return nil
}

/*
// validateSignatureSimple validates and shows ONLY true or false
func validateSignatureSimple(inputFile string) error {
	file, err := os.Open(inputFile)
	if err != nil {
		fmt.Println("false")
		return nil
	}
	defer file.Close()

	response, err := verify.VerifyFile(file)
	if err != nil {
		fmt.Println("false")
		return nil
	}

	// Check if there's at least one VALID signature
	hasValidSignature := false
	for _, signer := range response.Signers {
		// Use the actual field we saw in the structure: valid_signature
		if signer.ValidSignature {
			hasValidSignature = true
			break
		}
	}

	if hasValidSignature {
		fmt.Println("Verified: true")
	} else {
		fmt.Println("Verified: false")
	}

	return nil
}
*/

// validateSignatureSimple validates and shows validity for each signer
func validateSignatureSimple(inputFile string) error {
	file, err := os.Open(inputFile)
	if err != nil {
		fmt.Println("Error opening file")
		return nil
	}
	defer file.Close()

	response, err := verify.VerifyFile(file)
	if err != nil {
		fmt.Println("Error validating signatures")
		return nil
	}

	// Check if there are any signatures
	if len(response.Signers) == 0 {
		fmt.Println("No signatures found")
		return nil
	}

	// Show validity for each signer
	for i, signer := range response.Signers {
		status := "INVALID"
		if signer.ValidSignature {
			status = "VALID"
		}
		
		// Get signer name or use placeholder
		signerName := signer.Name
		if signerName == "" {
			signerName = fmt.Sprintf("Signer %d", i+1)
		}
		
		fmt.Printf("Signer: %s - Status: %s\n", signerName, status)
	}

	// Also show overall summary
	validCount := 0
	for _, signer := range response.Signers {
		if signer.ValidSignature {
			validCount++
		}
	}
	
	fmt.Printf("\nSummary: %d of %d signatures are valid\n", validCount, len(response.Signers))
	
	if validCount == len(response.Signers) {
		fmt.Println("Overall: ALL signatures are valid")
	} else if validCount > 0 {
		fmt.Println("Overall: SOME signatures are valid")
	} else {
		fmt.Println("Overall: NO valid signatures")
	}

	return nil
}

func validateSignaturesSimpleWithCRL(inputFile string, crlFile string) error {
	file, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	var crl *x509.RevocationList
	if crlFile != "" {
		crl, err = loadCRLFromFile(crlFile)
		if err != nil {
			return fmt.Errorf("error loading CRL file: %w", err)
		}
	} else {
		fmt.Println("No CRL file provided — skipping local revocation check.")
	}

	// Configuração de verificação de assinaturas do PDF
	options := verify.DefaultVerifyOptions()
	options.EnableExternalRevocationCheck = false // evita download automático

	response, err := verify.VerifyFileWithOptions(file, options)
	if err != nil {
		return fmt.Errorf("error validating signatures: %w", err)
	}

	if len(response.Signers) == 0 {
		fmt.Println("No signatures found")
		return nil
	}

	fmt.Println("CRL Check Results:")
	fmt.Println("==================")

	revokedCount := 0
	for i, signer := range response.Signers {
		signerName := signer.Name
		if signerName == "" {
			signerName = fmt.Sprintf("Signer_%d", i+1)
		}

		status := "NOT REVOKED"

		// Verificação manual de CRL local
		if crl != nil && len(signer.Certificates) > 0 {
			// Pega o primeiro certificado da assinatura
			cert := signer.Certificates[0].Certificate
			signerSerial := cert.SerialNumber
			for _, revoked := range crl.RevokedCertificates {
				if revoked.SerialNumber.Cmp(signerSerial) == 0 {
					status = "REVOKED"
					revokedCount++
					break
				}
			}
		}

		fmt.Printf("%s: %s\n", signerName, status)
	}

	fmt.Printf("\nSummary: %d of %d signatures are revoked\n", revokedCount, len(response.Signers))
	if revokedCount > 0 {
		fmt.Println("Overall: Some signers are revoked")
	} else {
		fmt.Println("Overall: No revoked signers found")
	}

	return nil
}

func showKeyInfo(keyFile string) error {
	// Try to load as private key first
	privateKey, err := loadPrivateKey(keyFile)
	if err == nil {
		fmt.Printf("RSA private key loaded successfully:\n")
		fmt.Printf("  - Size: %d bits\n", privateKey.PublicKey.N.BitLen())
		fmt.Printf("  - Algorithm: RSA\n")
		fmt.Printf("  - Can be used for signing: YES\n")
		return nil
	}

	// Try to load as certificate
	cert, err := loadCertificate(keyFile)
	if err == nil {
		fmt.Printf("X.509 certificate loaded successfully:\n")
		fmt.Printf("  - Subject: %s\n", cert.Subject)
		fmt.Printf("  - Issuer: %s\n", cert.Issuer)
		fmt.Printf("  - Valid from: %s to %s\n", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
		fmt.Printf("  - Signature algorithm: %s\n", cert.SignatureAlgorithm)
		fmt.Printf("  - Serial number: %s\n", cert.SerialNumber)
		fmt.Printf("  - Can be used for signing: YES\n")
		return nil
	}

	return fmt.Errorf("file is not a valid private key or certificate")
}

func main() {
	// Command flags
	cmdAddPassword := flag.Bool("add-password", false, "Add password to PDF")
	cmdRemovePassword := flag.Bool("remove-password", false, "Remove password from PDF")
	cmdSign := flag.Bool("sign", false, "Sign PDF with timestamp")
	cmdValidateSig := flag.Bool("validate-sig", false, "Validate signatures")
	cmdValidateSigDetailed := flag.Bool("validate-sig-detailed", false, "Validate signatures in detail")
	cmdValidateSigSimple := flag.Bool("validate-sig-simple", false, "Validate signatures (true/false)")
	cmdValidateSigSimpleWithCRL := flag.Bool("validate-sig-simple-crl", false, "Validate signatures (true/false)")
	cmdValidate := flag.Bool("validate", false, "Validate PDF")
	cmdKeyInfo := flag.Bool("key-info", false, "Display key information")

	// Parameter flags
	input := flag.String("input", "", "Input PDF file")
	crl := flag.String("crl", "", "Input CRL file")
	output := flag.String("output", "", "Output PDF file")
	userPass := flag.String("user", "", "User password")
	ownerPass := flag.String("owner", "", "Owner password")
	keyFile := flag.String("key", "", "Private key file")
	certFile := flag.String("cert", "", "Certificate file")

	flag.Parse()

	var err error

	switch {
	case *cmdAddPassword:
		if *input == "" || *output == "" {
			fmt.Println("Error: -input and -output are required")
			return
		}
		// At least one password must be provided
		if *userPass == "" && *ownerPass == "" {
			fmt.Println("Error: At least one password (-user or -owner) must be provided")
			return
		}
		err = addPassword(*input, *output, *userPass, *ownerPass)

	case *cmdRemovePassword:
		if *input == "" || *output == "" {
			fmt.Println("Error: -input and -output are required")
			return
		}
		// At least one password must be provided
		if *userPass == "" && *ownerPass == "" {
			fmt.Println("Error: At least one password (-user or -owner) must be provided")
			return
		}
		err = removePassword(*input, *output, *userPass, *ownerPass)

	case *cmdSign:
		if *input == "" || *output == "" || *keyFile == "" || *certFile == "" {
			fmt.Println("Error: -input, -output, -key and -cert are required")
			return
		}
		err = signPDFWithTimestamp(*input, *output, *keyFile, *certFile)

	case *cmdValidateSig:
		if *input == "" {
			fmt.Println("Error: -input is required")
			return
		}
		err = validateSignatures(*input)

	case *cmdValidateSigDetailed:
		if *input == "" {
			fmt.Println("Error: -input is required")
			return
		}
		err = validateSignaturesDetailed(*input)

	case *cmdValidateSigSimple:
		if *input == "" {
			fmt.Println("Error: -input is required")
			return
		}
		err = validateSignatureSimple(*input)

	case *cmdValidateSigSimpleWithCRL:
		if *input == "" {
			fmt.Println("Error: -input is required")
			return
		}
		err = validateSignaturesSimpleWithCRL(*input, *crl)

	case *cmdValidate:
		if *input == "" {
			fmt.Println("Error: -input is required")
			return
		}
		err = validatePDF(*input, *userPass, *ownerPass)

	case *cmdKeyInfo:
		if *keyFile == "" {
			fmt.Println("Error: -key is required")
			return
		}
		err = showKeyInfo(*keyFile)

	default:
		fmt.Println("Usage: pdfcrypt [COMMAND] [OPTIONS]")
		fmt.Println("\nCommands (flags):")
		fmt.Println("  -add-password                   Add password to PDF")
		fmt.Println("  -remove-password                Remove password from PDF")
		fmt.Println("  -sign                           Sign PDF with timestamp")
		fmt.Println("  -validate-sig                   Validate signatures")
		fmt.Println("  -validate-sig-detailed          Validate signatures in detail")
		fmt.Println("  -validate-sig-simple            Validate signatures (true/false)")
		fmt.Println("  -validate-sig-simple-crl        Validate signatures against a CRL")
		fmt.Println("  -validate                       Validate PDF")
		fmt.Println("  -key-info                       Display key/certificate information")
		fmt.Println("\nExamples:")
		fmt.Println("  pdfcrypt -add-password -input doc.pdf -output enc.pdf -user 123 -owner 456")
		fmt.Println("  pdfcrypt -remove-password -input enc.pdf -output doc.pdf -user 123 -owner 456")
		fmt.Println("  pdfcrypt -sign -input doc.pdf -output sign.pdf -key key.pem -cert cert.pem")
		fmt.Println("  pdfcrypt -validate-sig -input sign.pdf")
		return
	}

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	} else {
		fmt.Println("Operation completed successfully!")
	}
}
