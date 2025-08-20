package mitm

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/e2b-dev/infra/packages/shared/pkg/keys"
)

type SecretResolver func(uuid string) (string, error)

func processE2BHeaders(headers http.Header, resolver SecretResolver) {
	// the placeholders are the uuidv4 ids of the secrets in postgres with the format e2b_<uuid>
	uuidRegex := regexp.MustCompile(keys.SecretPrefix + `([[:xdigit:]]{8}(?:\-[[:xdigit:]]{4}){3}\-[[:xdigit:]]{12})`)

	for headerName, headerValues := range headers {
		for i, value := range headerValues {
			matches := uuidRegex.FindAllStringSubmatch(value, -1)
			if len(matches) == 0 {
				continue
			}

			newValue := value
			for _, match := range matches {
				if len(match) != 2 {
					continue
				}

				fullMatch := match[0]
				uuid := match[1]

				replacement, err := resolver(uuid)
				if err != nil {
					// should probably properly handle the error here
					continue
				}

				newValue = strings.ReplaceAll(newValue, fullMatch, replacement)
			}

			headers[headerName][i] = newValue
		}
	}
}
