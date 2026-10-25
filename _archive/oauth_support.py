#!/usr/bin/env python3
from authlib.integrations.flask_client import OAuth
from flask import Flask

oauth = OAuth()

def init_oauth(app):
    oauth.init_app(app)
    
    # Google OAuth
    google = oauth.register(
        name='google',
        client_id='YOUR_GOOGLE_CLIENT_ID',
        client_secret='YOUR_GOOGLE_CLIENT_SECRET',
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'}
    )
    
    # GitHub OAuth
    github = oauth.register(
        name='github',
        client_id='YOUR_GITHUB_CLIENT_ID',
        client_secret='YOUR_GITHUB_CLIENT_SECRET',
        access_token_url='https://github.com/login/oauth/access_token',
        access_token_params=None,
        authorize_url='https://github.com/login/oauth/authorize',
        authorize_params=None,
        api_base_url='https://api.github.com/',
        client_kwargs={'scope': 'user:email'}
    )
    
    return google, github

# Routes:
@app.route('/auth/google')
def google_login():
    """Initiate Google OAuth flow"""
    redirect_uri = url_for('google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/auth/github')
def github_login():
    """Initiate GitHub OAuth flow"""
    redirect_uri = url_for('github_callback', _external=True)
    return oauth.github.authorize_redirect(redirect_uri)
