#!/usr/bin/python

import sqlite3, sys, argparse

'''                                                                        
Author: Ian Ahl, 1aN0rmus@TekDefense.com
Created: 02/25/2013
'''

# location of the MASTIFF sqlite DB
mastiffDB = '/opt/malware/APT1/log/mastiff.db'
# Adding command options
parser = argparse.ArgumentParser(description='Generate HTML From a specified sqlite DB')
parser.add_argument('-d', '--database', help='Select the database you want to use')
parser.add_argument('-o', '--output', help='Output filename')
args = parser.parse_args()
if args.database:
    mastiffDB=args.database
if args.output != None:
    print '[*] Printing results to file:', args.output
    output = ""
    output = str(args.output)
    o = open(output, "w")
    sys.stdout = o 
# CSS from http://pythoughts.com/table-style-css/
print '''
<style type="text/css">
#table-3 {
    border: 1px solid #DFDFDF;
    background-color: #F9F9F9;
    width: 100%;
    -moz-border-radius: 3px;
    -webkit-border-radius: 3px;
    border-radius: 3px;
    font-family: Arial,"Bitstream Vera Sans",Helvetica,Verdana,sans-serif;
    color: #333;
}
#table-3 td, #table-3 th {
    border-top-color: white;
    border-bottom: 1px solid #DFDFDF;
    color: #555;
}
#table-3 th {
    text-shadow: rgba(255, 255, 255, 0.796875) 0px 1px 0px;
    font-family: Georgia,"Times New Roman","Bitstream Charter",Times,serif;
    font-weight: normal;
    padding: 7px 7px 8px;
    text-align: left;
    line-height: 1.3em;
    font-size: 14px;
}
#table-3 td {
    font-size: 12px;
    padding: 4px 7px 2px;
    vertical-align: top;
}
h1 {
    text-shadow: rgba(255, 255, 255, 0.796875) 0px 1px 0px;
    font-family: Georgia,"Times New Roman","Bitstream Charter",Times,serif;
    font-weight: normal;
    padding: 7px 7px 8px;
    text-align: Center;
    line-height: 1.3em;
    font-size: 40px;
}
h2 {
    text-shadow: rgba(255, 255, 255, 0.796875) 0px 1px 0px;
    font-family: Georgia,"Times New Roman","Bitstream Charter",Times,serif;
    font-weight: normal;
    padding: 7px 7px 8px;
    text-align: left;
    line-height: 1.3em;
    font-size: 16px;
}
</style>
'''
# Connect to the MASTIFF DB
con = sqlite3.connect(mastiffDB)

with con:    
    
    cur = con.cursor()    
    # SQL Query
    cur.execute("SELECT type, count(*) AS total FROM mastiff GROUP BY type ORDER BY total DESC")
    # SQL Server Results
    rows = cur.fetchall()
    # Generate HTML
    print '''
    <html>
    <body>
    <title> MASTIFF DB Results </title>
    <h1> MASTIFF DB Results </h1>
    <h2> Count of File Types </h2>
    <table id="table-3">
    <tr>
    <th>File Type</th>
    <th>Count</th>
    </tr>
    '''
    # Generate Table data from the DB
    for row in rows:
        print ('<tr><td>' + str(row[0]) + '</td><td>' + str(row[1]) + '</td>' + '<td></tr>') 
    print '</table>'
    print '<br>'
    
    # SQL Query
    cur.execute("SELECT * FROM MASTIFF")
    # SQL Server Results
    rows = cur.fetchall()
    print '''
    </table>
    <br>
    <table id="table-3">
    <h2> Sample Details </h2>
    <tr>
    <th>ID</th>
    <th>MD5</th>
    <th>File Type</th>
    <th>Fuzzy Hash</th>
    </tr>
    '''
    # Generate Table data from the DB    
    for row in rows:
        print ('<tr><td>' + str(row[0]) + '</td><td>' + str(row[1]) + '</td><td>' + str(row[4]) + '</td><td>' + str(row[5]) + '</td><td></tr>')
    print '''
    </table>
    <br>
    <br>
    <h4>Created using @TekDefense MASTIFF2HTML.py  www.tekdefense.com; https://github.com/1aN0rmus/TekDefense</h4>
    </body>
    </html>
    '''
