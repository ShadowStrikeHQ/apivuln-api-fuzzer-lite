# apivuln-API-Fuzzer-Lite
A lightweight fuzzer that generates semi-random API requests based on a provided OpenAPI/Swagger specification, focusing on edge cases and boundary conditions. It uses `requests` and `jsonschema` to validate requests and responses against the schema, reporting deviations. - Focused on Automated tools to scan REST APIs for common vulnerabilities like injection flaws, broken authentication, and data exposure. These tools use OpenAPI specifications (Swagger/JSON) or generate requests based on fuzzing techniques to identify potential weaknesses in API endpoints and data handling. They don't require significant system installations and focus on testing API security from an external perspective.

## Install
`git clone https://github.com/ShadowStrikeHQ/apivuln-api-fuzzer-lite`

## Usage
`./apivuln-api-fuzzer-lite [params]`

## Parameters
- `-h`: Show help message and exit
- `--requests`: Number of requests to send per endpoint. Defaults to 10.
- `--dry-run`: Perform a dry run without sending actual requests.

## License
Copyright (c) ShadowStrikeHQ
