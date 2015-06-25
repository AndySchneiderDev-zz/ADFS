param(
    [Parameter()][ValidateSet('Windows','UserName')] $ClientCredentialType="UserName",
    [Parameter(Mandatory=$true)] $Server,
    [Parameter()] $AppliesTo = "urn:adfsmonitor",
    [Parameter()] $Username ="",
    [Parameter()] $Password="",
    [Parameter()] $Domain ="",
    [Parameter()][ValidateSet('1','2')] $SAMLVersion = 2,
    [Parameter()][ValidateSet('Token','RSTR')] $OutputType = 'Token',
    [Parameter()]$Cred = (Get-Credential)

)

$IgnoreCertificateErrors = $true
$ADFSTrustPath = 'adfs/services/trust/13'
$SecurityMode = 'TransportWithMessageCredential'
$ADFSBaseUri = "https://$server"

switch ($ClientCredentialType) {
    'Windows' {
        $MessageCredential = 'Windows'
        $ADFSTrustEndpoint = 'windowsmixed'
    }
    'UserName' {
        $MessageCredential = 'UserName'
        $ADFSTrustEndpoint = 'usernamemixed'
    }
}


if($cred) {

$Username = $cred.UserName
$Password = $cred.GetNetworkCredential().Password
# ADFS 3 requires upn for usernames when hitting active auth endpoints
# requires may be strong word.. this was a hack that worked :) 
# therefore we don't care about domain, but set it foo
$Domain = "foo"

}


$Credential = New-Object System.Net.NetworkCredential -ArgumentList $Username,$Password,$Domain
Add-Type -AssemblyName 'System.ServiceModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
Add-Type -AssemblyName 'System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'

$Binding = New-Object -TypeName System.ServiceModel.WS2007HttpBinding -ArgumentList ([System.ServiceModel.SecurityMode] $SecurityMode)
$Binding.Security.Message.EstablishSecurityContext = $false
$Binding.Security.Message.ClientCredentialType = $MessageCredential
$Binding.Security.Transport.ClientCredentialType = 'None'

$EP = New-Object -TypeName System.ServiceModel.EndpointAddress -ArgumentList ('{0}/{1}/{2}' -f $ADFSBaseUri,$ADFSTrustPath,$ADFSTrustEndpoint)

$WSTrustChannelFactory = New-Object -TypeName System.ServiceModel.Security.WSTrustChannelFactory -ArgumentList $Binding, $EP
$WSTrustChannelFactory.TrustVersion = [System.ServiceModel.Security.TrustVersion]::WSTrust13
$WSTrustChannelFactory.Credentials.Windows.ClientCredential = $Credential
$WSTrustChannelFactory.Credentials.UserName.UserName = $Credential.UserName
$WSTrustChannelFactory.Credentials.UserName.Password = $Credential.Password
$Channel = $WSTrustChannelFactory.CreateChannel()

$TokenType = @{
    SAML11 = 'urn:oasis:names:tc:SAML:1.0:assertion'
    SAML2 = 'urn:oasis:names:tc:SAML:2.0:assertion'
}

$RST = New-Object -TypeName System.IdentityModel.Protocols.WSTrust.RequestSecurityToken -Property @{
    RequestType   = [System.IdentityModel.Protocols.WSTrust.RequestTypes]::Issue
    AppliesTo     = $AppliesTo
    KeyType       = [System.IdentityModel.Protocols.WSTrust.KeyTypes]::Bearer
    TokenType     = if ($SAMLVersion -eq '2') {$TokenType.SAML2} else {$TokenType.SAML11}
}

$RSTR = New-Object -TypeName System.IdentityModel.Protocols.WSTrust.RequestSecurityTokenResponse


try {
    $OriginalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    if ($IgnoreCertificateErrors) {[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {return $true}}
    $Token = $Channel.Issue($RST, [ref] $RSTR)
}
finally {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $OriginalCallback
}


if ($OutputType -eq 'RSTR') {
    Write-Output -InputObject $RSTR
} else {
    new-object psobject -Property @{
            "ClaimType" = $token.TokenXml.AttributeStatement.Attribute.Name
            "ClaimValue" = $token.TokenXml.AttributeStatement.Attribute.AttributeValue
            "Server" = $Server
            }
}

}

