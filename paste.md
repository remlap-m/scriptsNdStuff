{
    "definition": {
        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
        "contentVersion": "1.0.0.0",
        "triggers": {
            "Microsoft_Sentinel_incident": {
                "type": "ApiConnectionWebhook",
                "inputs": {
                    "host": {
                        "connection": {
                            "name": "@parameters('$connections')['azuresentinel']['connectionId']"
                        }
                    },
                    "body": {
                        "callback_url": "@{listCallbackUrl()}"
                    },
                    "path": "/incident-creation"
                }
            }
        },
        "actions": {
            "Get_Title": {
                "runAfter": {},
                "type": "Compose",
                "inputs": "@triggerBody()?['object']?['properties']?['title']"
            },
            "Get_Severity": {
                "runAfter": {},
                "type": "Compose",
                "inputs": "@triggerBody()?['object']?['properties']?['severity']"
            },
            "Get_IncidentNumber": {
                "runAfter": {},
                "type": "Compose",
                "inputs": "@triggerBody()?['object']?['properties']?['incidentNumber']"
            },
            "Get_Incident_URL": {
                "runAfter": {},
                "type": "Compose",
                "inputs": "@triggerBody()?['object']?['properties']?['incidentUrl']"
            },
            "Get_AlertCount": {
                "runAfter": {},
                "type": "Compose",
                "inputs": "@triggerBody()?['object']?['properties']?['additionalData']?['alertsCount']"
            },
            "Get_Entities": {
                "runAfter": {},
                "type": "Compose",
                "inputs": "@coalesce(triggerBody()?['object']?['properties']?['relatedEntities'], json('[]'))"
            },
            "Get_Alerts": {
                "runAfter": {},
                "type": "Compose",
                "inputs": "@coalesce(triggerBody()?['object']?['properties']?['Alerts'], json('[]'))"
            },
            "Init_Variables": {
                "runAfter": {
                    "Get_Entities": [
                        "Succeeded"
                    ],
                    "Get_Alerts": [
                        "Succeeded"
                    ],
                    "Get_Title": [
                        "Succeeded"
                    ],
                    "Get_Severity": [
                        "Succeeded"
                    ],
                    "Get_IncidentNumber": [
                        "Succeeded"
                    ],
                    "Get_Incident_URL": [
                        "Succeeded"
                    ],
                    "Get_AlertCount": [
                        "Succeeded"
                    ]
                },
                "type": "InitializeVariable",
                "inputs": {
                    "variables": [
                        {
                            "name": "Entities_List",
                            "type": "array"
                        },
                        {
                            "name": "Alert_Descriptions",
                            "type": "array"
                        },
                        {
                            "name": "Alert_Times",
                            "type": "array"
                        },
                        {
                            "name": "Custom_Details_List",
                            "type": "array"
                        }
                    ]
                }
            },
            "For_each_Entity": {
                "foreach": "@outputs('Get_Entities')",
                "runAfter": {
                    "Init_Variables": [
                        "Succeeded"
                    ]
                },
                "type": "Foreach",
                "runtimeConfiguration": {
                    "concurrency": {
                        "repetitions": 1
                    }
                },
                "actions": {
                    "Skip_unnamed_entities": {
                        "runAfter": {},
                        "type": "If",
                        "expression": {
                            "and": [
                                {
                                    "not": {
                                        "equals": [
                                            "@coalesce(items('For_each_Entity')?['properties']?['friendlyName'], '')",
                                            ""
                                        ]
                                    }
                                }
                            ]
                        },
                        "actions": {
                            "Add_to_Entities_Variable": {
                                "runAfter": {},
                                "type": "AppendToArrayVariable",
                                "inputs": {
                                    "name": "Entities_List",
                                    "value": "@concat(coalesce(items('For_each_Entity')?['kind'], 'Entity'), ': ', items('For_each_Entity')?['properties']?['friendlyName'])"
                                }
                            }
                        },
                        "else": {
                            "actions": {}
                        }
                    }
                }
            },
            "For_each_Alert": {
                "foreach": "@outputs('Get_Alerts')",
                "runAfter": {
                    "For_each_Entity": [
                        "Succeeded",
                        "Failed",
                        "Skipped",
                        "TimedOut"
                    ]
                },
                "type": "Foreach",
                "runtimeConfiguration": {
                    "concurrency": {
                        "repetitions": 1
                    }
                },
                "actions": {
                    "Skip_alerts_without_times": {
                        "runAfter": {},
                        "type": "If",
                        "expression": {
                            "and": [
                                {
                                    "not": {
                                        "equals": [
                                            "@coalesce(items('For_each_Alert')?['properties']?['startTimeUtc'], '')",
                                            ""
                                        ]
                                    }
                                }
                            ]
                        },
                        "actions": {
                            "Append_Alert_Time": {
                                "runAfter": {},
                                "type": "AppendToArrayVariable",
                                "inputs": {
                                    "name": "Alert_Times",
                                    "value": "@concat(convertTimeZone(items('For_each_Alert')?['properties']?['startTimeUtc'], 'UTC', 'GMT Standard Time', 'dd MMM HH:mm'), ' - ', convertTimeZone(coalesce(items('For_each_Alert')?['properties']?['endTimeUtc'], items('For_each_Alert')?['properties']?['startTimeUtc']), 'UTC', 'GMT Standard Time', 'HH:mm'))"
                                }
                            }
                        },
                        "else": {
                            "actions": {}
                        }
                    },
                    "Skip_empty_descriptions": {
                        "runAfter": {
                            "Skip_alerts_without_times": [
                                "Succeeded",
                                "Failed",
                                "Skipped",
                                "TimedOut"
                            ]
                        },
                        "type": "If",
                        "expression": {
                            "and": [
                                {
                                    "not": {
                                        "equals": [
                                            "@coalesce(items('For_each_Alert')?['properties']?['description'], '')",
                                            ""
                                        ]
                                    }
                                }
                            ]
                        },
                        "actions": {
                            "Append_Alert_Description": {
                                "runAfter": {},
                                "type": "AppendToArrayVariable",
                                "inputs": {
                                    "name": "Alert_Descriptions",
                                    "value": "@items('For_each_Alert')?['properties']?['description']"
                                }
                            }
                        },
                        "else": {
                            "actions": {}
                        }
                    },
                    "Skip_empty_custom_details": {
                        "runAfter": {
                            "Skip_empty_descriptions": [
                                "Succeeded",
                                "Failed",
                                "Skipped",
                                "TimedOut"
                            ]
                        },
                        "type": "If",
                        "expression": {
                            "and": [
                                {
                                    "not": {
                                        "equals": [
                                            "@string(coalesce(items('For_each_Alert')?['properties']?['additionalData']?['Custom Details'], ''))",
                                            ""
                                        ]
                                    }
                                },
                                {
                                    "not": {
                                        "equals": [
                                            "@string(coalesce(items('For_each_Alert')?['properties']?['additionalData']?['Custom Details'], ''))",
                                            "{}"
                                        ]
                                    }
                                }
                            ]
                        },
                        "actions": {
                            "Append_Custom_Details": {
                                "runAfter": {},
                                "type": "AppendToArrayVariable",
                                "inputs": {
                                    "name": "Custom_Details_List",
                                    "value": "@string(items('For_each_Alert')?['properties']?['additionalData']?['Custom Details'])"
                                }
                            }
                        },
                        "else": {
                            "actions": {}
                        }
                    }
                }
            },
            "Send_Slack_message_to_Tickets_channel": {
                "runAfter": {
                    "For_each_Alert": [
                        "Succeeded",
                        "Failed",
                        "Skipped",
                        "TimedOut"
                    ]
                },
                "type": "Http",
                "inputs": {
                    "uri": "https://hooks.slack.com/services/<REDACTED>",
                    "method": "POST",
                    "headers": {
                        "Content-Type": "application/json"
                    },
                    "body": {
                        "text": "Sentinel incident #@{outputs('Get_IncidentNumber')}: @{outputs('Get_Title')}",
                        "blocks": [
                            {
                                "type": "divider"
                            },
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": "*#@{outputs('Get_IncidentNumber')} @{outputs('Get_Title')}*"
                                }
                            },
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": "*Alert times:*\n@{if(empty(variables('Alert_Times')), '_not available_', concat('• ', join(union(variables('Alert_Times'), variables('Alert_Times')), concat(decodeUriComponent('%0A'), '• '))))}"
                                }
                            },
                            {
                                "type": "section",
                                "fields": [
                                    {
                                        "type": "mrkdwn",
                                        "text": "*Severity:*\n@{coalesce(outputs('Get_Severity'), 'Unknown')}"
                                    },
                                    {
                                        "type": "mrkdwn",
                                        "text": "*Alerts:*\n@{coalesce(outputs('Get_AlertCount'), 0)}"
                                    }
                                ]
                            },
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": "*Description:*\n@{if(empty(variables('Alert_Descriptions')), '_none_', join(union(variables('Alert_Descriptions'), variables('Alert_Descriptions')), concat(decodeUriComponent('%0A'), decodeUriComponent('%0A'))))}"
                                }
                            },
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": "*Entities:*\n@{if(empty(variables('Entities_List')), '_none resolved_', concat('• ', join(union(variables('Entities_List'), variables('Entities_List')), concat(decodeUriComponent('%0A'), '• '))))}"
                                }
                            },
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": "*Custom details:*\n@{if(empty(variables('Custom_Details_List')), '_none_', concat('```', join(union(variables('Custom_Details_List'), variables('Custom_Details_List')), decodeUriComponent('%0A')), '```'))}"
                                }
                            },
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": "@{if(empty(coalesce(outputs('Get_Incident_URL'), '')), '_No incident link available_', concat('<', outputs('Get_Incident_URL'), '|View in Sentinel>'))}"
                                }
                            },
                            {
                                "type": "divider"
                            }
                        ]
                    }
                }
            }
        },
        "outputs": {},
        "parameters": {
            "$connections": {
                "type": "Object",
                "defaultValue": {}
            }
        }
    },
    "parameters": {
        "$connections": {
            "type": "Object",
            "value": {
                "azuresentinel": {
                    "id": "<REDACTED>",
                    "connectionId": "<REDACTED>",
                    "connectionName": "azuresentinel-Sentinel_Incident-Notify_via_Slack",
                    "connectionProperties": {
                        "authentication": {
                            "type": "ManagedServiceIdentity"
                        }
                    }
                }
            }
        }
    }
}
