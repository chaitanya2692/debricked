import json
from flask import Flask, request

import sqlalchemy as db
from sqlalchemy.orm import sessionmaker

app = Flask(__name__)

@app.route('/search_db', methods=['GET', 'POST']) #allow both GET and POST requests
def search_db():
    
    engine = db.create_engine('sqlite:///expo_database.db')
    connection = engine.connect()
    metadata = db.MetaData()
    cve = db.Table('CVE', metadata, autoload=True, autoload_with=engine)
    cpe = db.Table('CPE', metadata, autoload=True, autoload_with=engine)
    
    Session = sessionmaker(bind=engine)
    session = Session()
    
    if request.method == 'POST':  #this block is only entered when the form is submitted
        userquery = request.form.get('user_query').split('/')
        
        if 'cve' in userquery:
            cve_info = session.query(cve).filter_by(id=userquery[2]).all()[0]
            cpe_info = session.query(cpe.columns.cpe_id).filter(cpe.columns.cve_id==userquery[2]).all()
            return '''
                       <h1>CVE: {}</h1>
                       <h2>Description: {}</h2>
                       <h2>Last Modified Date: {}</h2>
                       <h2>Published Date: {}</h2>
                       <h2>CVSS3: {}</h2>
                       <h2>CPEs: {}</h2>'''.format(cve_info[0], cve_info[1], cve_info[2], cve_info[3], cve_info[4], cpe_info)
        
        elif 'cpe' in userquery:
            if len(userquery) == 4:
                cve_info = session.query(cpe.columns.cve_id).filter(cpe.columns.vendor==userquery[2], cpe.columns.product==userquery[3]).all()
            if len(userquery) == 3:
                cve_info = session.query(cpe.columns.cve_id).filter(cpe.columns.vendor==userquery[2]).all()
        
            return '''
                       <h1>CPE: {}</h1>
                       <h1>CVE: {}</h1>'''.format(userquery, cve_info)
        
        else:
            return '''<h1>Please try again</h1>'''
        

    return '''<form method="POST">
                  user_query: <input type="text" name="user_query"><br>
                  <input type="submit" value="Submit"><br>
              </form>'''

if __name__ == '__main__':
 
    app.run()