#!/usr/bin/python

import sqlite3, argparse, os

'''                                                                        
Author: Ian Ahl, 1aN0rmus@TekDefense.com
Created: 02/25/2013
'''

# variables
#mastiffDir = '/opt/work/log/' 
#dbName = 'mastiff.db'



# Adding command options
parser = argparse.ArgumentParser(description='Generate HTML From a specified sqlite DB')
parser.add_argument('-f', '--folder', help='Select the database directory. Must wnd in a "/". For example, /opt/work/log/')
parser.add_argument('-d', '--database', help='Enter a sqlite database name. For Example mastiff.db')
args = parser.parse_args()
if args.database:
    dbName=args.database
if args.folder:
    mastiffDir = args.folder
mastiffDB = mastiffDir + dbName
wwwDir = mastiffDir + 'www/'
if os.path.exists(mastiffDir + 'www'):
    pass
else:
    os.mkdir(mastiffDir + 'www')
# Connect to the MASTIFF DB
con = sqlite3.connect(mastiffDB)

with con:    
    
    cur = con.cursor()    
    # SQL Query
    cur.execute("SELECT * FROM MASTIFF")
    
    
    
    # SQL Server Results
    rows = cur.fetchall()
    

    # Generate Table data from the DB    
    print '[*] Generating mastiff.hmtl in ' + wwwDir
    for row in rows:
        uid = str(row[0])
        md5 = str(row[1])
        fileType = str(row[4])
        fuzzy = str(row[5])
        tableData = '<tr><td>' + uid + '</td><td><a href ="' + wwwDir + md5 + '.html">' + md5 + '</a></td><td>' + fileType + '</td><td>' + fuzzy + '</td><td></tr>'
        if os.path.isfile(wwwDir + 'mastiff.html'):
            f = open(wwwDir + 'mastiff.html', 'a')
            f.write(tableData)
        else:
            f = open(wwwDir + 'mastiff.html', "w")
            f.write('''
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
            <html>
            <body>
            <title> MASTIFF DB Results </title>
            <h1> MASTIFF DB Results </h1>
            <table id="table-3">
            <h2> Sample Details </h2>
            <tr>
            <th>ID</th>
            <th>MD5</th>
            <th>File Type</th>
            <th>Fuzzy Hash</th>
            </tr>
            '''
            + tableData
            )        
    f = open(wwwDir + 'mastiff.html', 'a')
    f.write(
        '''    
        </table>
        <br>
        <br>
        <h4>Created using @TekDefense MASTIFF2HTML.py  www.tekdefense.com; https://github.com/1aN0rmus/TekDefense</h4>
        </body>
        </html>
        ''')
    print '[*] Creating table in masitff.db called extended. May take a moment.'
    cur.execute('DROP TABLE IF EXISTS extended')
    cur.execute('CREATE TABLE extended(Id INTEGER PRIMARY KEY, md5 TEXT, Files TEXT)')
    con.commit()
    for r, d, f in os.walk(mastiffDir):
        for files in d:
            if len(files) == 32:
                md5 = files
                subDir = mastiffDir + md5 + '/'
                for r, d, f in os.walk(subDir):
                    for files2 in f:
                        inserter = md5 + ',' + files2
                        cur.execute('INSERT INTO extended(md5,Files) VALUES (?,?);', (md5,files2))
                        con.commit()
                  
    # SQL Query
    cur.execute('SELECT * FROM extended')
    con.text_factory = str
    # SQL Server Results
    rows = cur.fetchall()
    
    for row in rows:
        uid = str(row[0])
        md5 = str(row[1])
        fileName = str(row[2])
        print '[*] Generating html for each sample ' + wwwDir + md5 + '.html'
        tableData = '<tr><td>' + uid + '</td><td>' + md5 + '</td><td><a href ="' + mastiffDir + md5 + '/' + fileName +'">' + fileName + '</a></td></tr>'
        if os.path.isfile(wwwDir + md5 + '.html'):
            f = open(wwwDir + md5 + '.html', 'a')
            f.write(tableData)
        else:
            f = open(wwwDir + md5 + '.html', "w")
            f.write('''
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
            <html>
            <body>
            <title> MASTIFF DB Results </title>
            <h1> MASTIFF Malware Analysis Result </h1>
            <table id="table-3">
            <tr>
            <th>id</th>
            <th>md5</th>
            <th>Results</th>
            </tr>
            '''
            + tableData
            )
        
    # SQL Query
    cur.execute('SELECT DISTINCT md5 FROM extended')
    con.text_factory = str
    # SQL Server Results
    rows = cur.fetchall()
    
    for row in rows:
        md5 = str(row[0])        
        f = open(wwwDir + md5 + '.html', 'a')    
        f.write('''
        </table>
        <br>
        <br>
        <h6>Created using @TekDefense MASTIFF2HTML.py  www.tekdefense.com; https://github.com/1aN0rmus/TekDefense</h6>
        </body>
        </html>
        ''')
    print '[+] Operation complete'
    print '[*] View results at ' + wwwDir + 'mastiff.html'
    
