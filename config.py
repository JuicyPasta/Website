class Config(object):
    DEBUG = True
    DEVELOPMENT = True

class ProductionConfig(Config):
    DEVELOPMENT = False
    DEBUG = False


