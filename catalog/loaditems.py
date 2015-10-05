from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, CategoryItem, User

engine = create_engine('postgresql:///catalog')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="Jerry Ferrer", email="jerrysferrer@gmail.com",
             picture='https://lh6.googleusercontent.com/-PPRm_OlhT2I/AAAAAAAAAAI/AAAAAAAAAIE/CHNmQpaaB5k/photo.jpg')
session.add(User1)
session.commit()

User2 = User(name="Twitter Bird", email="twitterbird@twitter.com",
             picture='https://pbs.twimg.com/profile_images/2284174872/7df3h38zabcvjylnyfe3_bigger.png')
session.add(User2)
session.commit()

# Items for Soccer
category1 = Category(user_id=1, name="Soccer")
session.add(category1)
session.commit()

# Items for Basketball
category1 = Category(user_id=1, name="Basketball")
session.add(category1)
session.commit()

catItem1 = CategoryItem(user_id=1, name="Ball", description="Description: Professional indoor ball", picture="/static/img/upload.jpg", cat_id=category1.id)
session.add(catItem1)
session.commit()

# Items for Baseball
category1 = Category(user_id=1, name="Baseball")
session.add(category1)
session.commit()

catItem1 = CategoryItem(user_id=1, name="Bat", description="Description: Wooden baseball bat", picture="/static/img/upload.jpg", cat_id=category1.id)
session.add(catItem1)
session.commit()

# Items for Frisbee
category1 = Category(user_id=1, name="Frisbee")
session.add(category1)
session.commit()

# Items for Snowboarding
category1 = Category(user_id=2, name="Snowboarding")
session.add(category1)
session.commit()

# Items for Rock Climbing
category1 = Category(user_id=1, name="Rock Climbing")
session.add(category1)
session.commit()

# Items for Foosball
category1 = Category(user_id=1, name="Foosball")
session.add(category1)
session.commit()

# Items for Skating
category1 = Category(user_id=2, name="Skating")
session.add(category1)
session.commit()

# Items for Hockey
category1 = Category(user_id=2, name="Hockey")
session.add(category1)
session.commit()

catItem1 = CategoryItem(user_id=2, name="Hockey Gears", description="Description: Hockey gears - stick, skate, etc.", picture="/static/img/upload.jpg", cat_id=category1.id)
session.add(catItem1)
session.commit()

catItem2 = CategoryItem(user_id=2, name="Puck", description="Description: Blue hocky puck", picture="/static/img/upload.jpg", cat_id=category1.id)
session.add(catItem2)
session.commit()

print "added catalog items!"
