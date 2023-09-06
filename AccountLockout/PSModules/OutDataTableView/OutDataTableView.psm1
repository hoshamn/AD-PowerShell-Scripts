<#
 .SYNOPSIS

  Generates an HTM/HTML file based on powershell object input to create a searchable jquery datatables page.

 .DEPENDENCIES

  demo_page.css
  demo_table.css
  demo_table_jui.css
  jquery-ui-1.8.4.custom.css
  jquery.js
  jquery.dataTables.js

 .COMPATABILITY

  Tested for: PS v3+

 .NOTES

  TAKEN FROM: http://www.dougfinke.com/blog/index.php/2011/02/15/how-to-send-powershell-output-to-a-jquery-interactive-datatable-in-a-web-browser/

  NAME:       OutDataTableView.psm1

  AUTHOR:     Doug Fink

  MODIFIED:   Josh Tessaro

  LASTEDIT:   11/18/13
#>

###
# NOTE: aaSorting dictates default sort column, See below for examples.
# http://datatables.net/examples/basic_init/table_sorting.html
###
Function Get-DataTableHtml {
	function ql {$args}

	$imports = ql demo_page.css demo_table.css demo_table_jui.css jquery-ui-1.8.4.custom.css | % {
		$fileName = ($_).Replace("\", "/")
		"@import '$fileName';"
	}

@"
<html>
	<head>
        <meta http-equiv="cache-control" content`"max-age=0" />
        <meta http-equiv="cache-control" content="no-cache" />
        <meta http-equiv="expires" content="0" />
        <meta http-equiv="expires" content="Tue, 01 Jan 1980 1:00:00 GMT" />
        <meta http-equiv="pragma" content="no-cache" />
        <META HTTP-EQUIV="refresh" CONTENT="300">
		<style type="text/css" title="currentStyle">
			$($imports)
		</style>
        

		<script type="text/javascript" language="javascript" src="jquery.js"></script>
		<script type="text/javascript" language="javascript" src="jquery.dataTables.js"></script>

        <script type="text/javascript" charset="utf-8">
			`$( function() {
				`$('#example').dataTable({
                    "bProcessing": true,
                    "bJQueryUI": true,
                    "sPaginationType": "full_numbers",
                    "aaSorting": [[ 2, "desc" ]],
                    "aLengthMenu": [[15, 25, 50, 100], [15, 25, 50, 100]],
                    "iDisplayLength" : 15,
                    "aoColumns": [ null, null, null, { "bVisible": false }, { "bVisible": false } ]
                });
               `$(".display").fadeIn("slow");
			} );
		</script>

	</head>
<body>
"@
}

<#
 .SYNOPSIS

  Generates an HTM/HTML file based on powershell object input to create a searchable jquery datatables page.

 .DEPENDENCIES

  Get-DataTableHtml
  
  demo_page.css
  demo_table.css
  demo_table_jui.css
  jquery-ui-1.8.4.custom.css
  jquery.js
  jquery.dataTables.js

 .PARAMETER  Properties

  The column headers for the objects being passed.

 .PARAMETER  PageHeader

  The Page header (HTML), displayed above the genereted Datatable.

 .PARAMETER  PageFooter

  The Page footer (HTML), displayed below the genereted Datatable.

 .PARAMETER  OutFile

  The file to which the generated webpage is to be written.

 .PARAMETER  View

  Open the generated webpage in the default web browser for review.

 .PARAMETER  Deploy

  Copy the dependencies to the destination directory (Same directory as the OutFile).

 .COMPATABILITY

  Tested for: PS v3+

 .NOTES

  TAKEN FROM: http://www.dougfinke.com/blog/index.php/2011/02/15/how-to-send-powershell-output-to-a-jquery-interactive-datatable-in-a-web-browser/

  NAME:       Out-DataTableView

  AUTHOR:     Doug Fink

  MODIFIED:   Josh Tessaro

  LASTEDIT:   11/18/13
#>
Function Out-DataTableView {
    param(
        [String[]]$Properties,
        [Alias('Title')]
        [Alias('Header')]
        [String]$PageHeader="TITLE",
        [Alias('Footer')]
        [String]$PageFooter="",
        [String]$OutFile=$(Join-Path $PSScriptRoot $(Split-Path -Leaf ([io.path]::GetTempFileName() -replace ".tmp",".htm"))),
        [Switch]$View,
        [Switch]$Deploy
    )

    begin {
        $result = @()
    }

    process {
        if(!$Global:HeadingsExported) {
            if(!$Properties) {
                $Properties = $_ |Get-Member -MemberType *Property | Select -ExpandProperty Name
            }

            $r += Get-DataTableHtml
            # Begin Body
            $r += $PageHeader

            $r += '<table cellpadding="0" cellspacing="0" border="0" id="example" class="display" style="display: none;">'
            $r += "`r`n<thead><tr>"
            ForEach($property in $Properties) {
                $r += "`r`n<th>$property</th>"
            }
            $r += "</tr></thead><tbody>"

            $Global:HeadingsExported = "finished"
        }

        $r += "<tr>"
        ForEach($property in $Properties) {
            $r += "<td>$($_.$Property)</td>"
        }
        $r += "</tr>"
    }

    end {

        $r += "</tbody></table>`n`r"
        $r +=  $PageFooter
        # End Body
        $r +=  "`n`r</body></html>"

        $r | Set-Content -Encoding ascii $OutFile

        If($Deploy)
        {
            # Copy Necessary files to Website directory if they dont exist.
            foreach($file in 'demo_page.css', 'demo_table.css','demo_table_jui.css', 'jquery-ui-1.8.4.custom.css', 'jquery.js', 'jquery.dataTables.js')
            {
                If(-not (Test-Path "$(Split-Path -Parent $OutFile)\$file"))
                {
                    Copy-Item "$((get-module OutDataTableView).ModuleBase)\$file" "$(Split-Path -Parent $OutFile)\"
                }
            }
        }
        
        If($View)
        {
            Invoke-Item $OutFile
        }
        try{
            Remove-Item Variable:HeadingsExported
        }catch{}
    }
}

$psscriptroot = Split-Path -Parent $MyInvocation.MyCommand.Path
dir $psscriptroot *.htm | rm
Set-Alias odv Out-DataTableView
Export-ModuleMember -Alias odv -Function Out-DataTableView
# SIG # Begin signature block
# MIIEMAYJKoZIhvcNAQcCoIIEITCCBB0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQURzNXW+ysF3SDFbxQ8YT7LGSC
# nOugggI6MIICNjCCAaOgAwIBAgIQGyVCx+51BaZN/TtU8y6kkTAJBgUrDgMCHQUA
# MCwxKjAoBgNVBAMTIVBvd2VyU2hlbGwgTG9jYWwgQ2VydGlmaWNhdGUgUm9vdDAe
# Fw0xMzA4MjMxODA5MDFaFw0zOTEyMzEyMzU5NTlaMBcxFTATBgNVBAMTDEpvc2gg
# VGVzc2FybzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1P5MVsMsmjh0hJM7
# WfJ9a+dsCfRlrqyU5/a1jSKqzVjGqWj+BJoJqRbYxaJloCrLHZDS4WrbH9yaMpkU
# JhNTBt87wPROzhRecV8hVBsRy++YJ9+3O+Q3AtCQ6JW30U3pXGGHxiYBORqWUyIG
# +LKKgrOthw9uswLjeZMdPTA/FcUCAwEAAaN2MHQwEwYDVR0lBAwwCgYIKwYBBQUH
# AwMwXQYDVR0BBFYwVIAQP9IkDaLZr6h8rp1Ol1kzZKEuMCwxKjAoBgNVBAMTIVBv
# d2VyU2hlbGwgTG9jYWwgQ2VydGlmaWNhdGUgUm9vdIIQKWjfp+EDEbRAyi6ZRpo+
# PDAJBgUrDgMCHQUAA4GBAIP+QPDnatl31dxRVDCRP0rng+K57Ma5rhgxhLBDAc5I
# FdMUoDIkEwtcQdYqbMXkdFBJNAs1Xg4npy5cvQl1AzKJqyODX+EqYmmqDciPPrAE
# jebetNAFOVrcX77XTommxkSYPqCKxrlCxrPlvXOYaO3FLnZ5xXWhwH5gFknmRyzl
# MYIBYDCCAVwCAQEwQDAsMSowKAYDVQQDEyFQb3dlclNoZWxsIExvY2FsIENlcnRp
# ZmljYXRlIFJvb3QCEBslQsfudQWmTf07VPMupJEwCQYFKw4DAhoFAKB4MBgGCisG
# AQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFLX9
# eBsCEa0lY03C8cJ2xfyhG+LVMA0GCSqGSIb3DQEBAQUABIGADYRH4NSDpbhbXY4G
# xkH+NUXfVWo7uvZH7tagff+w1/YDjvfTmJ5b7OIf4Pkr3ZEO2pujW2BW5pPrdo7E
# TOqyuWMfyy/y0hzlPWZN50bZVIZ2T7hN9HfM7FpxuK+Tm3F+3SNIKZnXY95rfLBz
# lUXLUuKOU1cssQCbkj4rxkrhZRQ=
# SIG # End signature block
