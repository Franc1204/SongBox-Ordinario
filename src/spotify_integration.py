# spotify_integration.py

import os
import spotipy
from spotipy.oauth2 import SpotifyOAuth
import time

def create_spotify_oauth(user_email):
    redirect_uri = os.getenv("SPOTIFY_REDIRECT_URI")
    return SpotifyOAuth(
        client_id=os.getenv("SPOTIFY_CLIENT_ID"),
        client_secret=os.getenv("SPOTIFY_CLIENT_SECRET"),
        redirect_uri=redirect_uri,
        scope="user-read-email user-top-read user-read-recently-played",
        cache_path=None
    )

def get_valid_spotify_token(user_email, mongo):
    try:
        user = mongo.db.users.find_one({'email': user_email})
        if not user:
            print(f"[ERROR] Usuario con email {user_email} no encontrado en la base de datos.")
            return None

        token_info = {
            'access_token': user.get('spotify_access_token'),
            'refresh_token': user.get('spotify_refresh_token'),
            'expires_at': user.get('spotify_token_expires_at')
        }

        if not token_info['access_token']:
            print(f"[ERROR] Token de acceso no encontrado para {user_email}.")
            return None

        if token_info['expires_at'] - int(time.time()) < 60:
            print(f"[TOKEN EXPIRED] Intentando refrescar token para {user_email}...")
            sp_oauth = create_spotify_oauth(user_email)
            try:
                token_info = sp_oauth.refresh_access_token(token_info['refresh_token'])
                mongo.db.users.update_one(
                    {'email': user_email},
                    {'$set': {
                        'spotify_access_token': token_info['access_token'],
                        'spotify_refresh_token': token_info.get('refresh_token', token_info['refresh_token']),
                        'spotify_token_expires_at': token_info['expires_at']
                    }}
                )
                print(f"[SPOTIFY REFRESH] Token actualizado para {user_email}.")
            except Exception as e:
                print(f"[ERROR] Error al refrescar el token: {e}")
                return None

        return token_info['access_token']

    except Exception as e:
        print(f"[ERROR] Error en get_valid_spotify_token: {e}")
        return None

def verify_entity_exists(entity_type, entity_id, sp):
    try:
        if entity_type == 'album':
            sp.album(entity_id)
        elif entity_type == 'artist':
            sp.artist(entity_id)
        elif entity_type == 'song':
            sp.track(entity_id)
        else:
            return False  # Tipo de entidad inválido
        return True  # Si no hay excepciones, la entidad existe
    except spotipy.exceptions.SpotifyException as e:
        print(f"[ERROR] La entidad no existe en Spotify: {e}")
        return False
