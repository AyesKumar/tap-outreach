# tap-outreach

[Singer](https://www.singer.io/) tap that extracts data from a [Outreach](https://www.outreach.io/) database and produces JSON-formatted data following the [Singer spec](https://github.com/singer-io/getting-started/blob/master/SPEC.md).

This tap:

- Pulls raw data from [Outreach](https://api.outreach.io/api/v2/docs)
- Extracts the following resources:
  - [Prospects](https://api.outreach.io/api/v2/prospects)
  - [Sequences](https://api.outreach.io/api/v2/sequences)
  - [FIXME](http://example.com)
- Outputs the schema for each resource
- Incrementally pulls data based on the input state

**Available Outreach Scopes**

Available scopes: profile, email, create_prospects, read_prospects, update_prospects, read_sequences, update_sequences, read_tags, read_accounts, create_accounts, read_activities, read_mailings, read_mappings, read_plugins, read_users, create_calls, read_calls, read_call_purposes, read_call_dispositions, accounts.all, accounts.read, accounts.write, accounts.delete, callDispositions.all, callDispositions.read, callDispositions.write, callDispositions.delete, callPurposes.all, callPurposes.read, callPurposes.write, callPurposes.delete, calls.all, calls.read, calls.write, calls.delete, events.all, events.read, events.write, events.delete, mailings.all, mailings.read, mailings.write, mailings.delete, mailboxes.all, mailboxes.read, mailboxes.write, mailboxes.delete, personas.all, personas.read, personas.write, personas.delete, prospects.all, prospects.read, prospects.write, prospects.delete, sequenceStates.all, sequenceStates.read, sequenceStates.write, sequenceStates.delete, sequenceSteps.all, sequenceSteps.read, sequenceSteps.write, sequenceSteps.delete, sequences.all, sequences.read, sequences.write, sequences.delete, stages.all, stages.read, stages.write, stages.delete, taskPriorities.all, taskPriorities.read, taskPriorities.write, taskPriorities.delete, users.all, users.read, users.write, users.delete, tasks.all, tasks.read, tasks.write, tasks.delete, snippets.all, snippets.read, snippets.write, snippets.delete, templates.all, templates.read, templates.write, templates.delete, rulesets.all, rulesets.read, rulesets.write, rulesets.delete, opportunities.all, opportunities.read, opportunities.write, opportunities.delete, opportunityStages.all, opportunityStages.read, opportunityStages.write, opportunityStages.delete, sequenceTemplates.all, sequenceTemplates.read, sequenceTemplates.write, sequenceTemplates.delete, customValidations.all, customValidations.read, customValidations.write, customValidations.delete, webhooks.all, webhooks.read, webhooks.write, webhooks.delete, teams.all, teams.read, teams.write, teams.delete, mailboxContacts.all, mailboxContacts.read, mailboxContacts.write, mailboxContacts.delete, meetingTypes.all, meetingTypes.read, meetingTypes.write, meetingTypes.delete, experiments.all, experiments.read, experiments.write, experiments.delete, phoneNumbers.all, phoneNumbers.read, phoneNumbers.write, phoneNumbers.delete, meetingFields.all, meetingFields.read, meetingFields.write, meetingFields.delete, customDuties.all, customDuties.read, customDuties.write, customDuties.delete, duties.all, duties.read, duties.write, duties.delete, favorites.all, favorites.read, favorites.write, favorites.delete, emailAddresses.all, emailAddresses.read, emailAddresses.write, emailAddresses.delete

# Quickstart

## Install the tap

```
> pip install tap-outreach
```

## Create a Config file

```
{
  "client_id": "secret_client_id",
  "client_secret": "secret_client_secret",
  "refresh_token": "abc123",
  "start_date": "2017-11-02T00:00:00Z",
  "select_fields_by_default": true
}
```

The `client_id` and `client_secret` keys are your OAuth Salesforce App secrets. The `refresh_token` is a secret created during the OAuth flow. For more info on the Salesforce OAuth flow, visit the [Outreach documentation](https://api.outreach.io/api/v2/docs#authentication).

The `start_date` is used by the tap as a bound on SOQL queries when searching for records.  This should be an [RFC3339](https://www.ietf.org/rfc/rfc3339.txt) formatted date-time, like "2018-01-08T00:00:00Z". For more details, see the [Singer best practices for dates](https://github.com/singer-io/getting-started/blob/master/BEST_PRACTICES.md#dates).

## Run Discovery

To run discovery mode, execute the tap with the config file.

```
> tap-outreach --config config.json --discover > properties.json
```

## Sync Data

To sync data, select fields in the `properties.json` output and run the tap.

```
> tap-outreach --config config.json --properties properties.json [--state state.json]
```

---

Copyright &copy; 2018 Stitch
