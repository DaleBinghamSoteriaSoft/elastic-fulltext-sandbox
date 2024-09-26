# elastic-fulltext-sandbox

Thjis is a demo C# console client to connect into Elastic Stack in OpenRMF Professional, load sample checklist/patch/other data and then see how to full text index and query it.

Initial work was talked about with Scott Karter as well as tychon.io and others at NGA for full text searching.

## Create the Index and Mapping

do a PUT command to the <ELK-ROOT-URL>/openrmfpro-checklists/ and pass this JSON body to create the index with specific mapping

```
{
		"mappings": {
			"properties": {
				"artifactId": {
					"type": "keyword"
				},
				"cciList": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				},
				"checkContent": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				},
				"checklistRelease": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				},
				"checklistTitle": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				},
				"checklistType": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				},
				"checklistTypeSanitized": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				},
				"checklistVersion": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				},
				"comments": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				},
				"created": {
					"type": "date"
				},
				"createdBy": {
					"type": "text",
          "index": false
				},
				"createdByName": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				},
				"deleted": {
					"type": "boolean"
				},
				"details": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				},
				"discussion": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				},
				"fixText": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				},
				"groupTitle": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				},
				"hostname": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				},
				"internalIdString": {
					"type": "keyword"
				},
				"isWebDatabaseApplication": {
					"type": "boolean"
				},
				"locked": {
					"type": "boolean"
				},
				"ruleId": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				},
				"ruleTitle": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				},
				"ruleVersion": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				},
				"severity": {
					"type": "keyword"
				},
				"severityCategory": {
					"type": "long"
				},
				"severityJustification": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				},
				"severityOverride": {
					"type": "keyword"
				},
				"status": {
					"type": "keyword"
				},
				"systemGroupId": {
					"type": "keyword"
				},
				"systemKey": {
					"type": "keyword"
				},
				"systemTitle": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				},
				"version": {
					"type": "long"
				},
				"vulnid": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				},
				"webDatabaseApplicationInstance": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				},
				"webDatabaseApplicationSite": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword",
							"ignore_above": 256
						}
					}
				}
			}
		}
	}
```