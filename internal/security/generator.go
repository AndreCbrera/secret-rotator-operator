package security

import (
	"bytes" // Usamos bytes.Buffer para máxima compatibilidad con el entorno Docker
	"crypto/rand"
	"fmt"
	"math/big"
)

// Definición de caracteres
const (
	CharUpper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	CharLower   = "abcdefghijklmnopqrstuvwxyz"
	CharDigits  = "0123456789"
	CharSymbols = "~!@#$%^&*()_+`-={}|[]\\:\"<>?,./"
)

// GeneratePassword crea una contraseña aleatoria de longitud dada,
// usando crypto/rand como fuente de entropía segura.
func GeneratePassword(length int, includeSymbols bool) (string, error) {
	var characterSet bytes.Buffer // Inicializamos bytes.Buffer

	// Siempre incluimos los caracteres básicos para garantizar una alta seguridad
	characterSet.WriteString(CharUpper)
	characterSet.WriteString(CharLower)
	characterSet.WriteString(CharDigits)

	if includeSymbols {
		characterSet.WriteString(CharSymbols)
	}

	set := characterSet.String()

	if set == "" || length <= 0 {
		return "", fmt.Errorf("conjunto de caracteres vacío o longitud no válida")
	}

	password := make([]byte, length)
	maxIndex := big.NewInt(int64(len(set)))

	// Llenar la contraseña usando la entropía segura del sistema
	for i := 0; i < length; i++ {
		// rand.Reader es la fuente de entropía criptográficamente segura.
		idxBig, err := rand.Int(rand.Reader, maxIndex)
		if err != nil {
			return "", fmt.Errorf("fallo al obtener número aleatorio seguro: %w", err)
		}
		password[i] = set[idxBig.Int64()]
	}

	return string(password), nil
}
