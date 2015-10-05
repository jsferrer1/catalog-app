#!/usr/bin/env python

"""File name: database_setup.py 
   The purpose of this program is to create the database with its
   corresponding classes, primary keys, foreign keys, and relationships.
   
   A serialize function is also included to facilitate a json output.
   
   Relationships include:
   - A user can have one-to-many categories and items
   - A category can have one-to-many items
"""

__author__      = "Jerry Ferrer"
__copyright__   = "Copyright (c) 2015"

from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
 
Base = declarative_base()

class User(Base):
    __tablename__ = 'user'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

class Category(Base):
    __tablename__ = 'category'
   
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    items = relationship("CategoryItem", backref="category", cascade="delete, delete-orphan")

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'id'          : self.id,
           'name'        : self.name,
           'Item'        : self.items
       }
 
class CategoryItem(Base):
    __tablename__ = 'category_item'


    id = Column(Integer, primary_key=True)
    name =Column(String(80), nullable=False)
    description = Column(String(250))
    picture = Column(String(80))
    cat_id = Column(Integer, ForeignKey('category.id'))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'cat_id'        : self.cat_id,
           'description'   : self.description,
           'id'            : self.id,
           'name'          : self.name
       }


engine = create_engine('postgresql:///catalog')
 

Base.metadata.create_all(engine)
