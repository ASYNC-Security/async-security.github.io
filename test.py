from pypsrp.wsman import WSMan
from pypsrp.powershell import RunspacePool, PowerShell

wsman = WSMan( 
    server="PORTICUS.jess.kingdom",
    username="Doros_ARCHIVON",
    password="bO3n21E6rc", 
    ssl=False
)

with RunspacePool(wsman) as pool:
    ps = PowerShell(pool)
    ps.add_cmdlet("Get-Command")
    ps.invoke()

    for output in ps.output:
        print(output)
    
    if ps.had_errors:
        for error in ps.streams.error:
            print(error)