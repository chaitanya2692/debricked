import sqlalchemy as db
from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, ForeignKey, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, backref

import json

Base = declarative_base()

class CVE(Base):
    __tablename__ = 'CVE'

    id = Column(String, primary_key=True)
    description = Column(String)
    last_modified_date = Column(String)
    published_date = Column(String)
    score = Column(Float)
    def __repr__(self):
        return "<CVE(id='%s', description='%s', last_modified_date='%s', published_date='%s', score='%f')>" % (
            self.id, self.description, self.last_modified_date, self.published_date, self.score)
        
class CPE(Base):
    __tablename__ = 'CPE'

    id = db.Column(Integer , primary_key=True , autoincrement=True)
    cpe_id = Column(String)
    product = Column(String)
    vendor = Column(String)
    cve_id = db.Column(db.String, ForeignKey('CVE.id'))
    cve = relationship('CVE', backref='CPE')
    
    def __repr__(self):
        return "<CPE(cpe_id='%s', product_id='%s', vendor_id='%s', cve_id='%s')>" % (
            self.cpe_id, self.product_id, self.vendor_id, self.cve_id)

def make_cve(id, log, session):
    description = str(log['cve']['description']['description_data'][0]['value'])
    last_modified_date = str(log['lastModifiedDate'])
    published_date = str(log['publishedDate'])
    score = get_score(log)
    cve_entry = CVE(id = id, 
                    description = description, 
                    last_modified_date = last_modified_date, 
                    published_date = published_date, 
                    score = score)
    session.add(cve_entry)
    

def make_cpe(id, node, session):
    for log in node:
      a = log.get('children', [])
      b = log.get('cpe_match', [])
      cpe_match = a or b
      for cpe_info in cpe_match:
        cpe_23_uri = cpe_info.get('cpe23Uri', None)
        if cpe_23_uri:
          cpe_id = cpe_23_uri
          raw_info = cpe_23_uri.split(':')
          product_name = raw_info[4]
          vendor_name = raw_info[3]
          cpe_entry = CPE(cpe_id =cpe_id,
                          product=product_name, 
                          vendor=vendor_name, 
                          cve_id=id)
          session.add(cpe_entry)
 
def get_score(log):
    try:
        score = float(log['impact']['baseMetricV3']['cvssV3']['baseScore'])
    except:
        score = None
    return score

if __name__ == '__main__':
    engine = create_engine('sqlite:///expo_database.db', echo=True)
    Session = sessionmaker(bind=engine)
    session = Session()
    Base.metadata.create_all(engine)
    
    with open('data.json') as json_file:
        data = json.load(json_file)

    for log in data:
        id = str(log['cve']['CVE_data_meta']['ID'])
        assert id is not None
        make_cve(id, log, session)
        make_cpe(id, log['configurations']['nodes'], session)
    
    session.commit()
    
'''

To query all CVEs related to that particular CPE
session.query(CPE.cve_id).filter_by(vendor_id='microsoft', product_id='windows_10').distinct(CPE.cve_id).all()

To get id, description, last_modified_date, published_date, score related to the CVE
session.query(CVE).filter_by(id='CVE-2019-1067').all()

To get CPE related to the CVE
session.query(CPE.cpe_id).filter_by(cve_id='CVE-2019-1067').all()

'''


    
    
    