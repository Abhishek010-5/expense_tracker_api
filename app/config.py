from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env')
    
    # database related
    database_url: str
    database_name: str
    
    # jwt related
    secret_key:str
    algorithm:str
    access_token_expire_minutes:int
    
    # redis db credentila and url
    redis_host:str
    redis_port:int
    redis_username:str
    redis_password:str
    redis_database:str
    
    # for mail
    mail_password:str
    mail:str
    
    # api key
    api_key:str

settings = Settings()


