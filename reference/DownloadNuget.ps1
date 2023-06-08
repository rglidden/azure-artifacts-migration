# --- settings ---
# use nuget v2 feed for this script
# v2 feed is sometimes same url as v3, just change /v3/index.json to /v2/ 

$feedUrlBase = "http://nexus.brockhome.net/repository/nuget-brock/"  # be sure to include trailing slash 

# the rest will be params when converting to funclet
$latest = $false
$overwrite = $true
$top = $null #use $top = $null to grab all , otherwise use number
$destinationDirectory = "/home/rglidden/NuGetLocal"

# --- locals ---
$webClient = New-Object System.Net.WebClient

# following is required if authenticating to TFS using integrated credentials
$webClient.UseDefaultCredentials=$true


# --- functions ---

# download entries on a page, recursively called for page continuations
function DownloadEntries {
 param ([string]$feedUrl) 
 $feed = [xml]$webClient.DownloadString($feedUrl)
 $entries = $feed.feed.entry 
 $progress = 0
            
 foreach ($entry in $entries) {
    $url = $entry.content.src
    if ($entry.title.InnerText -eq "")
    {
	# Write-Host "Skipping entry with empty title."
        continue;
    }
    # Write-host $entry.title.InnerText
    $fileName = $entry.title.InnerText + "-" + $entry.properties.version + ".nupkg"
    $saveFileName = join-path $destinationDirectory $fileName
    $pagepercent = ((++$progress)/$entries.Length*100)
    if ((-not $overwrite) -and (Test-Path -path $saveFileName)) 
    {
        write-progress -activity "$fileName already downloaded" `
                       -status "$pagepercent% of current page complete" `
                       -percentcomplete $pagepercent
        continue
    }
    write-progress -activity "Downloading $fileName" `
                   -status "$pagepercent% of current page complete" `
                   -percentcomplete $pagepercent

    [int]$trials = 0
    do {
        try {
            $trials +=1
            $webClient.DownloadFile($url, $saveFileName)
            break
        } catch [System.Net.WebException] {
            write-host "Problem downloading $url `tTrial $trials `
                       `n`tException: " $_.Exception.Message
        }
    }
    while ($trials -lt 3)
  }

  $link = $feed.feed.link | where { $_.rel.startsWith("next") } | select href
  if ($link -ne $null) {
    # if using a paged url with a $skiptoken like 
    # http:// ... /Packages?$skiptoken='EnyimMemcached-log4net','2.7'
    # remember that you need to escape the $ in powershell with `
    return $link.href
  }
  return $null
}  

# the NuGet feed uses a fwlink which redirects
# using this to follow the redirect
function GetPackageUrl {
 param ([string]$feedUrlBase) 
 $resp = [xml]$webClient.DownloadString($feedUrlBase)
 return $resp.service.GetAttribute("xml:base")
}

# --- do the actual work ---

# if dest dir doesn't exist, create it
if (!(Test-Path -path $destinationDirectory)) { 
    New-Item $destinationDirectory -type directory 
}

# set up feed URL
$serviceBase = $feedUrlBase
$feedUrl = $serviceBase + "Packages"
if($latest) {
    $feedUrl = $feedUrl + "?`$filter=IsLatestVersion eq true"
    if($top -ne $null) {
        $feedUrl = $feedUrl + "&`$orderby=DownloadCount desc&`$top=$top"
    }
}

while($feedUrl -ne $null) {
    Write-Host $feedUrl
    $feedUrl = DownloadEntries $feedUrl
}

