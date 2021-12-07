package config

var schema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "TODO",
  "title": "Consul ECS Configuration",
  "description": "A configuration for consul-ecs",
  "type": "object",
  "properties": {
    "aclTokenSecret": {
      "description": "Configure the ACL token secret provider",
      "type": "object",
      "properties": {
        "provider": {
          "type": "string",
          "enum": ["secret-manager"]
        },
        "configuration": {
          "type": "object",
          "properties": {
            "prefix": {
              "type": "string"
            },
            "consulClientTokenSecretArn": {
              "type": "string"
            }
          },
          "required": ["prefix", "consulClientTokenSecretArn"],
          "additionalProperties": false
        }
      },
      "required": ["provider", "configuration"],
      "additionalProperties": false
    },
    "mesh": {
      "description": "Configure the Consul mesh",
      "type": "object",
      "properties": {
        "service": {
          "type": "object",
          "properties": {
            "name": {
              "type": "string"
            },
            "port": {
              "type": "integer"
            },
            "checks": {
              "type": "array",
              "items": {
                "type": "string"
              },
              "uniqueItems": true
            },
            "meta": {
              "type": "object"
            },
            "tags": {
              "type": "array",
              "items": {
                "type": "string"
              },
              "uniqueItems": true
            }
          },
          "requires": ["port"],
          "additionalProperties": false
        },
        "bootstrapDir": {
          "type": "string"
        },
        "healthSyncContainers": {
          "type": "array",
          "items": {
            "type": "string"
          },
          "minItems": 1,
          "uniqueItems": true
        },
        "sidecar": {
          "type": "object",
          "properties": {
            "proxy": {
              "type": "object",
              "properties": {
                "upstreams": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "destinationName": {
                        "kind": "string"
                      },
                      "localBindPort": {
                        "kind": "integer"
                      }
                    },
                    "requires": ["destinationName", "localBindPort"],
                    "additionalProperties": false
                  }
                }
              },
              "additionalProperties": false
            }
          },
          "additionalProperties": false
        }
      },
      "requires": ["service", "bootstrapDir"],
      "additionalProperties": false
    }
  },
  "required": [ "aclTokenSecret", "mesh" ],
  "additionalProperties": false
}
`
