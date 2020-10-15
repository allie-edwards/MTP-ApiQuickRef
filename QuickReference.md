# Overview
### The purpose of thie document is to provide a quick reference to users looking to interact with KQL Queries in Microsoft Threat Protection from outside of the portal. It summarizes information from MS docs along with useful links, notes and code snippets.
#### Contents:
  
* [Creating an Access Token](#Creating-an-Access-Token)
    * Create an Access Token to authorize API calls
* [HTTP](#HTTP) 
    * Reference for calling the MTP API to return the results of a KQL query using a HTTP request
* [Powershell](#Powershell)
    * Reference for calling the MTP API to return the results of a KQL query using a Powershell script
    * Includes reference for automating Access Token generation on launch
* [Power Query M](#Power-Query-M)
    * Reference for adding the results of a MTP KQL query as a data source in Power BI
    * This method does **not** require the use of an Access Token and requires interactive login

# Creating an Access Token
### Guidance for creating an Access Token, which can then be used to Authorize API calls. 
#### Note:
* Access tokens expire after a set duration 
    * By default this is 1 hour for an Access Token and 90 days for a Refresh Token
    * Lifetimes can be configured with AzureAD Policy. Learn more about configuring token lifetimes [here](https://docs.microsoft.com/en-us/azure/active-directory/develop/configure-token-lifetimes)  
    * The [Powershell](#Powershell) section contains one potential solution to token expiration by generating a new Access Token when launching the ISE
* Learn more about access tokens [here.](https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens)  
#### Steps [1] and [2] below are summarized from [here.](https://docs.microsoft.com/en-us/microsoft-365/security/mtp/api-create-app-web?view=o365-worldwide)  
1. Create an App Registration. Learn more about App Registrations [here](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)  
    * Azure Portal
        * Navigate to the **Azure Active Directory** blade
        * Select **App Registration** and create a **New App Registration**
        * Note down the **Tenant ID** and **Application ID** of your new application ID
        * From **API Permissions** add **Application API Permissions** for **Microsoft Threat Protection:** *AdvancedHunting.Read*
        * From **Certificates and secrets** create a **New client secret** 
        * Note down the **Value** of your new secret
2. Generate Access Token using your desired language. Learn more about the protocol used [here](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)
<details>
<summary>Powershell</summary>

```powershell
# That code gets the App Context Token and save it to a file named "Latest-token.txt" under the current directory
# Paste below your Tenant ID, App ID and App Secret (App key).

$tenantId = '' ### Paste your tenant ID here
$appId = '' ### Paste your Application ID here
$appSecret = '' ### Paste your Application key here

$resourceAppIdUri = 'https://api.security.microsoft.com'
$oAuthUri = "https://login.windows.net/$TenantId/oauth2/token"
$authBody = [Ordered] @{
    resource = "$resourceAppIdUri"
    client_id = "$appId"
    client_secret = "$appSecret"
    grant_type = 'client_credentials'
}
$authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
$token = $authResponse.access_token
Out-File -FilePath "./Latest-token.txt" -InputObject $token
return $token
```
</details>
  
<p></p><p></p>  

<details>
<summary>Bash</summary> 

```bash
curl -i -X POST -H "Content-Type:application/x-www-form-urlencoded" -d "grant_type=client_credentials" -d "client_id=%CLIENT_ID%" -d "scope=https://securitycenter.onmicrosoft.com/windowsatpservice/.default" -d "client_secret=%CLIENT_SECRET%" "https://login.microsoftonline.com/%TENANT_ID%/oauth2/v2.0/token" -k
```
</details>

<p></p><p></p>   

# HTTP Request
### A brief summary on how to call the API using a HTTP request.
* Endpoint
    * `https://api.security.microsoft.com/api/advancedhunting/run/`
    * `Method: Post`
* Headers
    * Replace `{access token}` with an Access Token you have generated (see [here](#Creating-An-Access-Token))
    * `Authorization: Bearer {access token}`
    * `Content-Type: application/json`
* Body
    * Include your KQL Query in a JSON Body
    * Use a backslash to escape double quotes like `\"this\"`
    * `{ "Query":"IdentityLogonEvents | where Location == \"US\" and ActionType contains \"failed\"" }`

# Powershell
### A brief summary on how to call the API from Powershell.
* Configure your profile to request an Access Token on launch
    * Open your profile with `notepad $profile`
    * Copy the script below into your profile
        * Replace `{tenant-id}` and `{application-id}` with the respective values from your **App Registration**
        * Replace `{application-secret}` with the **Secret** created previously

<details>
<summary>Powershell</summary>

```powershell
$tenantId = '{tenant-id}'
$appId = '{application-id}'
$appSecret = '{application-secret}'

$resourceAppIdUri = 'https://api.security.microsoft.com'
$oAuthUri = "https://login.windows.net/$TenantId/oauth2/token"
$authBody = [Ordered] @{
    resource = "$resourceAppIdUri"
    client_id = "$appId"
    client_secret = "$appSecret"
    grant_type = 'client_credentials'
}
$authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
$token = $authResponse.access_token
```
</details>

<p></p><p></p>  

* Send your API request
    * Run the below script
        * Replace the value for `$query` with your KQL query
        * Use backtick to escape double quotes like  \`"this\`"  

<details>
<summary>Powershell</summary>

```powershell
$query = "IdentityLogonEvents | where Location == `"US`" and ActionType contains `"failed`""

$header = @{
    "Authorization" = "Bearer $token"
} 

$body = @{
    Query = "$query"
}

$bodyJson = $body | ConvertTo-Json

$parameters = @{
    Method = "Post"
    Uri = "https://api.security.microsoft.com/api/advancedhunting/run/"
    Headers = $header
    ContentType = "application/json"
    Body = $bodyJson
}

$response = Invoke-RestMethod @Parameters

$response | ConvertTo-Json
```
</details>

<p></p><p></p>  

# Power Query M
### Guidance for adding a MTP KQL Query as a data source in Power BI.
* From the **Home** ribbon select **Get Data** -> **Blank query**
* Right click on your query and open the **Advanced Editor** (or open it from the ribbon)
* In the query editor, replace the default content with the code block below (adapted from [here](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/api-power-bi))
* Replace the query in the second line with your own KQL
    * `*AdvancedHuntingQuery = "{your query here}"*)`
    * Use two sets of double quotes to escape double quotes like `""this""`
        * More info on M Structure is [here](https://docs.microsoft.com/en-us/powerquery-m/m-spec-lexical-structure)
* Close the advanced editor. When asked to authenticate select **Organizational Account** and provide credentials

<details>
<summary>M</summary>

```m
 	let 
        AdvancedHuntingQuery = "IdentityLogonEvents | where Location == ""US"" and ActionType contains ""failed""",

        HuntingUrl = "https://api.security.microsoft.com/api/advancedhunting",

        Response = Json.Document(Web.Contents(HuntingUrl, [Query=[key=AdvancedHuntingQuery]])),

        TypeMap = #table(
            { "Type", "PowerBiType" },
            {
                { "Double",   Double.Type },
                { "Int64",    Int64.Type },
                { "Int32",    Int32.Type },
                { "Int16",    Int16.Type },
                { "UInt64",   Number.Type },
                { "UInt32",   Number.Type },
                { "UInt16",   Number.Type },
                { "Byte",     Byte.Type },
                { "Single",   Single.Type },
                { "Decimal",  Decimal.Type },
                { "TimeSpan", Duration.Type },
                { "DateTime", DateTimeZone.Type },
                { "String",   Text.Type },
                { "Boolean",  Logical.Type },
                { "SByte",    Logical.Type },
                { "Guid",     Text.Type }
            }),

        Schema = Table.FromRecords(Response[Schema]),
        TypedSchema = Table.Join(Table.SelectColumns(Schema, {"Name", "Type"}), {"Type"}, TypeMap , {"Type"}),
        Results = Response[Results],
        Rows = Table.FromRecords(Results, Schema[Name]),
        Table = Table.TransformColumnTypes(Rows, Table.ToList(TypedSchema, (c) => {c{0}, c{2}}))

    in Table
```

</details>	