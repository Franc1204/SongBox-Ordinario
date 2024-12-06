from flask import Flask, request, jsonify, redirect, url_for
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone, timedelta
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, decode_token
from marshmallow import Schema, fields, ValidationError
from .spotify_integration import create_spotify_oauth, get_valid_spotify_token, verify_entity_exists
from werkzeug.utils import secure_filename
from bson.errors import InvalidId
from bson import ObjectId
from bson.objectid import ObjectId
from dotenv import load_dotenv
from flask_cors import CORS
import spotipy
import requests
import os
import json
import base64
import time
import logging

# Cargar las variables de entorno
load_dotenv()

app = Flask(__name__)

# Configuración de Flask y MongoDB
app.config["MONGO_URI"] = os.getenv('MONGO_URI')
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY')
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Leer la clave de API desde las variables de entorno
YOUTUBE_API_KEY = os.getenv("YOUTUBE_API_KEY")

# Inicializar JWT y MongoDB
mongo = PyMongo(app)
jwt = JWTManager(app)
CORS(app)

UPLOAD_FOLDER = 'static/uploads/profile_pictures'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


mongo.db.rates.create_index(
    [("entityType", 1), ("entityId", 1), ("userId", 1)],
    unique=True
)


# Crear la carpeta si no existe
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Extensiones permitidas
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Función para verificar si el archivo es válido
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Validación de datos de usuario con Marshmallow
class UserSchema(Schema):
    username = fields.Str(required=True)
    email = fields.Email(required=True)
    password = fields.Str(required=True)

user_schema = UserSchema()

@app.errorhandler(ValidationError)
def handle_validation_error(e):
    return jsonify({"error": e.messages}), 400

# ------------------------------ Rutas de Usuario ----------------------------------

# Endpoint para registro
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '').strip()

    if not username or not email or not password:
        return jsonify({'message': 'Todos los campos son obligatorios'}), 400

    # Verificar si el usuario ya existe
    existing_user = mongo.db.users.find_one({'email': email})
    if existing_user:
        return jsonify({'message': 'El usuario ya está registrado'}), 400

    # Crear el usuario
    hashed_password = generate_password_hash(password)
    user = {
        'username': username,
        'email': email,
        'password': hashed_password,
        'profile_picture': '/static/uploads/profile_pictures/default_picture.png',
        'favorites': []
    }
    mongo.db.users.insert_one(user)

    # Crear el token JWT
    access_token = create_access_token(identity=email)
    user_data = {
        'username': username,
        'email': email,
        'profile_picture': user['profile_picture'],
        'favorites': []
    }

    # Redirigir al flujo de autenticación de Spotify
    response = jsonify({'jwt': access_token, 'user': user_data})
    response.status_code = 201
    return response

# Endpoint para inicio de sesión
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        # Validar si el usuario existe
        user = mongo.db.users.find_one({'email': email})
        if not user or not check_password_hash(user['password'], password):
            return jsonify({'message': 'Correo o contraseña incorrectos'}), 401

        # Crear un token JWT para el usuario
        expires = timedelta(hours=1)
        jwt_token = create_access_token(identity=email, expires_delta=expires)

        # Devolver el token JWT y los datos del usuario
        user_data = {
            "username": user.get('username'),
            "email": user.get('email'),
            "profile_picture": user.get('profile_picture', ""),
            "favorites": user.get('favorites', []),
            "trivia_scores": user.get('trivia_scores', [])
        }
        return jsonify({
            "message": "Inicio de sesión exitoso",
            "jwt": jwt_token,
            "user": user_data
        }), 200

    except Exception as e:
        return jsonify({"message": f"Error al iniciar sesión: {str(e)}"}), 500

# Endpoint para iniciar la autenticación con Spotify
@app.route('/auth/spotify')
def auth_spotify():
    user_email = request.args.get('state')
    if not user_email:
        return jsonify({"error": "State parameter missing"}), 400
    sp_oauth = create_spotify_oauth(user_email)
    auth_url = sp_oauth.get_authorize_url(state=user_email)
    return redirect(auth_url)

# Endpoint para manejar el callback de Spotify
@app.route('/callback')
def spotify_callback():
    code = request.args.get('code')
    state = request.args.get('state')  # Esto es el email del usuario pasado como 'state'

    if not code or not state:
        return jsonify({"error": "Faltan los parámetros 'code' o 'state'."}), 400

    try:
        user_email = state  # Obtenemos el email del usuario desde 'state'

        # Obtener el token de acceso de Spotify
        sp_oauth = create_spotify_oauth(user_email)
        token_info = sp_oauth.get_access_token(code, as_dict=True)

        # Actualizar los datos del usuario con los tokens de Spotify
        mongo.db.users.update_one(
            {'email': user_email},
            {'$set': {
                'spotify_access_token': token_info['access_token'],
                'spotify_refresh_token': token_info.get('refresh_token'),
                'spotify_token_expires_at': token_info['expires_at']
            }}
        )

        # Crear un nuevo JWT que indica que la autenticación está completa
        new_jwt = create_access_token(identity=user_email)

        # Redirigir al frontend utilizando un deep link
        redirect_url = f'frontsb://login?token={new_jwt}'
        return redirect(redirect_url)

    except Exception as e:
        return jsonify({"error": f"Error en el callback de Spotify: {str(e)}"}), 400


@app.route('/update_profile_picture', methods=['POST'])
@jwt_required()
def update_profile_picture():
    if 'profile_picture' not in request.files:
        return jsonify({'message': 'No se encontró el archivo en la solicitud'}), 400
    file = request.files['profile_picture']
    if file.filename == '':
        return jsonify({'message': 'No se seleccionó ningún archivo'}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        user_email = get_jwt_identity()
        filename = f"user_{user_email}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Actualizar la foto de perfil del usuario en la base de datos
        user = mongo.db.users.find_one({'email': user_email})
        if user:
            profile_picture_url = f"/uploads/{filename}"  # Ruta accesible al frontend
            mongo.db.users.update_one(
                {'email': user_email},
                {'$set': {'profile_picture': profile_picture_url}}
            )
            return jsonify({'profile_picture': profile_picture_url}), 200
        else:
            return jsonify({'message': 'Usuario no encontrado'}), 404
    else:
        return jsonify({'message': 'Tipos de archivo permitidos: png, jpg, jpeg, gif'}), 400
    
@app.route('/update_username', methods=['POST'])
@jwt_required()
def update_username():
    data = request.get_json()
    new_username = data.get('username', '').strip()
    if not new_username:
        return jsonify({'message': 'El nombre de usuario no puede estar vacío'}), 400
    # Verificar si el nombre de usuario ya existe
    existing_user = mongo.db.users.find_one({'username': new_username})
    if existing_user:
        return jsonify({'message': 'El nombre de usuario ya está en uso'}), 400
    user_email = get_jwt_identity()
    user = mongo.db.users.find_one({'email': user_email})
    if user:
        mongo.db.users.update_one(
            {'email': user_email},
            {'$set': {'username': new_username}}
        )
        return jsonify({'username': new_username}), 200
    else:
        return jsonify({'message': 'Usuario no encontrado'}), 404


# ------------------------------ Endpoints de SearchScreen ----------------------------------

@app.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    try:
        current_user_email = get_jwt_identity()
        user = mongo.db.users.find_one({'email': current_user_email})
        if not user:
            return jsonify({"message": "Usuario no encontrado."}), 404

        user_data = {
            "id": str(user['_id']),
            "username": user.get('username'),
            "email": user.get('email'),
            "profile_picture": user.get('profile_picture', ""),
            "favorites": user.get('favorites', []),
            "trivia_scores": user.get('trivia_scores', []),
        }

        return jsonify({"user": user_data}), 200

    except Exception as e:
        return jsonify({"message": f"Error al obtener el usuario: {str(e)}"}), 500


@app.route('/search_song', methods=['GET'])
@jwt_required()
def search_song():
    current_user = get_jwt_identity()
    access_token = get_valid_spotify_token(current_user, mongo)
    if not access_token:
        return jsonify({"message": "Por favor, inicia sesión en Spotify para buscar canciones."}), 401

    query = request.args.get('q')
    limit = int(request.args.get('limit', 10))
    if not query:
        return jsonify({"message": "Se requiere un parámetro de búsqueda (q)"}), 400

    try:
        sp = spotipy.Spotify(auth=access_token)
        results = sp.search(q=query, type='track', limit=limit)
        tracks = []
        for item in results['tracks']['items']:
            track_info = {
                "id": item['id'],
                "name": item['name'],
                "artists": [artist['name'] for artist in item['artists']],
                "album": item['album']['name'],
                "url": item['external_urls']['spotify'],
                "preview_url": item.get('preview_url'),
                "cover_image": item['album']['images'][0]['url'] if item['album']['images'] else None
            }
            tracks.append(track_info)

        return jsonify({"tracks": tracks}), 200

    except Exception as e:
        return jsonify({"message": f"Error al buscar la canción: {str(e)}"}), 500


@app.route('/search_album', methods=['GET'])
@jwt_required()
def search_album():
    try:
        current_user = get_jwt_identity()
        access_token = get_valid_spotify_token(current_user, mongo)
        if not access_token:
            return jsonify({"message": "Por favor, inicia sesión en Spotify para buscar álbumes."}), 401

        query = request.args.get('q')
        limit = request.args.get('limit', 10)

        if not query:
            return jsonify({"message": "Se requiere un parámetro de búsqueda (q)"}), 400

        try:
            limit = int(limit)
        except ValueError:
            return jsonify({"message": "El parámetro 'limit' debe ser un número entero."}), 422

        sp = spotipy.Spotify(auth=access_token)
        results = sp.search(q=query, type='album', limit=limit)
        albums = []
        for item in results['albums']['items']:
            album_info = {
                "id": item['id'],
                "name": item['name'],
                "artist": [artist['name'] for artist in item['artists']],
                "release_date": item['release_date'],
                "total_tracks": item['total_tracks'],
                "url": item['external_urls']['spotify'],
                "cover_image": item['images'][0]['url'] if item['images'] else None
            }
            albums.append(album_info)

        return jsonify({"albums": albums}), 200

    except Exception as e:
        app.logger.error(f"Error al buscar el álbum: {str(e)}")
        return jsonify({"message": f"Error al buscar el álbum: {str(e)}"}), 500

    
@app.route('/search_artist', methods=['GET'])
@jwt_required()
def search_artist():
    current_user = get_jwt_identity()
    access_token = get_valid_spotify_token(current_user, mongo)
    if not access_token:
        return jsonify({"message": "Por favor, inicia sesión en Spotify para buscar artistas."}), 401

    query = request.args.get('q')
    limit = int(request.args.get('limit', 10))
    if not query:
        return jsonify({"message": "Se requiere un parámetro de búsqueda (q)"}), 400

    try:
        sp = spotipy.Spotify(auth=access_token)
        results = sp.search(q=query, type='artist', limit=limit)
        artists = []
        for item in results['artists']['items']:
            artist_info = {
                "id": item['id'],
                "name": item['name'],
                "genres": item['genres'],
                "popularity": item['popularity'],
                "followers": item['followers']['total'],
                "url": item['external_urls']['spotify'],
                "image": item['images'][0]['url'] if item['images'] else None
            }
            artists.append(artist_info)

        return jsonify({"artists": artists}), 200

    except Exception as e:
        return jsonify({"message": f"Error al buscar el artista: {str(e)}"}), 500
    

@app.route('/search_playlist', methods=['GET'])
@jwt_required()
def search_playlist():
    current_user = get_jwt_identity()
    access_token = get_valid_spotify_token(current_user, mongo)
    if not access_token:
        return jsonify({"message": "Por favor, inicia sesión en Spotify para buscar playlists."}), 401

    query = request.args.get('q')
    limit = int(request.args.get('limit', 10))
    if not query:
        return jsonify({"message": "Se requiere un parámetro de búsqueda (q)"}), 400

    try:
        sp = spotipy.Spotify(auth=access_token)
        results = sp.search(q=query, type='playlist', limit=limit)
        playlists = []
        for item in results['playlists']['items']:
            playlist_info = {
                "id": item['id'],
                "name": item['name'],
                "owner": item['owner']['display_name'],
                "url": item['external_urls']['spotify'],
                "image": item['images'][0]['url'] if item['images'] else None,
                "description": item.get('description', ''),
            }
            playlists.append(playlist_info)

        return jsonify({"playlists": playlists}), 200

    except Exception as e:
        return jsonify({"message": f"Error al buscar las playlists: {str(e)}"}), 500
    

@app.route('/search_profile', methods=['GET'])
@jwt_required()
def search_profile():
    query = request.args.get('q')
    limit = int(request.args.get('limit', 10))
    if not query:
        return jsonify({"message": "Se requiere un parámetro de búsqueda (q)"}), 400

    try:
        regex_query = {'$regex': query, '$options': 'i'}
        users = mongo.db.users.find(
            {
                '$or': [
                    {'username': regex_query},
                    {'email': regex_query}
                ]
            }
        ).limit(limit)

        profiles = []
        for user in users:
            profile_info = {
                "id": str(user['_id']),
                "username": user.get('username'),
                "email": user.get('email'),
                "profile_picture": user.get('profile_picture'),
                "favorites": user.get('favorites', []),
            }
            profiles.append(profile_info)

        return jsonify({"profiles": profiles}), 200

    except Exception as e:
        return jsonify({"message": f"Error al buscar perfiles: {str(e)}"}), 500


# ------------------------------ Endpoints de HomeScreen ----------------------------------

@app.route('/top_albums_global', methods=['GET'])
@jwt_required()
def top_albums_global():
    print("[DEBUG] Iniciando /top_albums_global")

    current_user = get_jwt_identity()
    print(f"[DEBUG] Usuario autenticado: {current_user}")

    access_token = get_valid_spotify_token(current_user, mongo)
    if not access_token:
        print("[ERROR] Token de acceso no disponible.")
        return jsonify({"message": "Por favor, inicia sesión en Spotify para ver los álbumes top."}), 401

    print(f"[DEBUG] Token de acceso obtenido: {access_token[:10]}...")  

    # Obtener parámetros de paginación
    try:
        limit = int(request.args.get('limit', 20))
        offset = int(request.args.get('offset', 0))
        if limit > 50:
            limit = 50  # Spotify API tiene un límite máximo de 50 por solicitud
    except ValueError:
        print("[ERROR] Parámetros de paginación inválidos.")
        return jsonify({"message": "Los parámetros 'limit' y 'offset' deben ser números enteros."}), 400

    try:
        sp = spotipy.Spotify(auth=access_token)
        print("[DEBUG] Cliente Spotify inicializado.")

        try:
            print("[DEBUG] Obteniendo nuevos lanzamientos de Spotify...")
            new_releases = sp.new_releases(limit=limit, offset=offset, country='US')
            print(f"[DEBUG] Nuevos lanzamientos obtenidos: {len(new_releases['albums']['items'])}")

            albums = []
            for album in new_releases['albums']['items']:
                album_info = {
                    "id": album['id'],
                    "name": album['name'],
                    "artists": [artist['name'] for artist in album['artists']],
                    "url": album['external_urls']['spotify'],
                    "cover_image": album['images'][0]['url'] if album['images'] else None,
                    "type": album['album_type']
                }
                albums.append(album_info)

            print(f"[DEBUG] Total de álbumes procesados: {len(albums)}")
            return jsonify({"albums": albums}), 200

        except spotipy.exceptions.SpotifyException as e:
            print(f"[ERROR] SpotifyException: {e}")
            print(f"Status Code: {e.http_status}")
            print(f"Error Message: {e.msg}")
            return jsonify({"message": f"Error con la API de Spotify: {e.msg}"}), e.http_status

    except Exception as e:
        print(f"[ERROR] Error general en /top_albums_global: {e}")
        return jsonify({"message": f"Error interno: {str(e)}"}), 500


@app.route('/top_artists_global', methods=['GET'])
@jwt_required()
def top_artists_global():
    print("[DEBUG] Iniciando /top_artists_global")

    current_user = get_jwt_identity()
    print(f"[DEBUG] Usuario autenticado: {current_user}")

    access_token = get_valid_spotify_token(current_user, mongo)
    if not access_token:
        print("[ERROR] Token de acceso no disponible.")
        return jsonify({"message": "Por favor, inicia sesión en Spotify para ver los artistas top."}), 401

    print(f"[DEBUG] Token de acceso obtenido: {access_token[:10]}...")  

    try:
        limit = int(request.args.get('limit', 20))
        offset = int(request.args.get('offset', 0))
        if limit > 50:
            limit = 50  
    except ValueError:
        print("[ERROR] Parámetros de paginación inválidos.")
        return jsonify({"message": "Los parámetros 'limit' y 'offset' deben ser números enteros."}), 400

    try:
        # Instanciar el cliente de Spotify con un timeout aumentado
        sp = spotipy.Spotify(auth=access_token, requests_timeout=30)
        print("[DEBUG] Cliente Spotify inicializado.")

        try:
            print("[DEBUG] Obteniendo nuevos lanzamientos de Spotify...")
            # Obtener nuevos lanzamientos
            new_releases = sp.new_releases(limit=50, country='US')  # Ajusta 'country' según tus necesidades
            print(f"[DEBUG] Nuevos lanzamientos obtenidos: {len(new_releases['albums']['items'])}")

            # Extraer artistas únicos de los nuevos lanzamientos
            artists_dict = {}
            for album in new_releases['albums']['items']:
                for artist in album['artists']:
                    artist_id = artist['id']
                    if artist_id not in artists_dict:
                        artists_dict[artist_id] = {
                            "id": artist_id,
                            "name": artist['name'],
                            "image": None,
                            "url": None,
                            "popularity": 0  
                        }

            # Obtener la información completa de los artistas
            artist_ids = list(artists_dict.keys())
            for i in range(0, len(artist_ids), 50):
                batch_ids = artist_ids[i:i + 50]
                try:
                    artists_info = sp.artists(batch_ids)['artists']
                except requests.exceptions.ReadTimeout:
                    print("[ERROR] Timeout al obtener detalles de artistas.")
                    return jsonify({"message": "La solicitud a Spotify ha tardado demasiado. Por favor, intenta nuevamente más tarde."}), 504
                except spotipy.exceptions.SpotifyException as e:
                    print(f"[ERROR] SpotifyException: {e}")
                    return jsonify({"message": f"Error con la API de Spotify: {e.msg}"}), e.http_status

                for artist_info in artists_info:
                    if artist_info:
                        artists_dict[artist_info['id']]['image'] = artist_info['images'][0]['url'] if artist_info['images'] else None
                        artists_dict[artist_info['id']]['url'] = artist_info['external_urls']['spotify']
                        artists_dict[artist_info['id']]['popularity'] = artist_info.get('popularity', 0)

            artists_list = list(artists_dict.values())

            # Ordenar los artistas por popularidad descendente
            artists_sorted = sorted(artists_list, key=lambda x: x['popularity'], reverse=True)

            paginated_artists = artists_sorted[offset:offset + limit]

            print(f"[DEBUG] Total de artistas procesados: {len(artists_sorted)}")
            print(f"[DEBUG] Artistas devueltos: {len(paginated_artists)}")

            response_artists = []
            for artist in paginated_artists:
                artist_info = {
                    "id": artist['id'],
                    "name": artist['name'],
                    "image": artist['image'],
                    "url": artist['url']
                }
                response_artists.append(artist_info)

            return jsonify({"artists": response_artists}), 200

        except requests.exceptions.ReadTimeout:
            print("[ERROR] Timeout al obtener nuevos lanzamientos de Spotify.")
            return jsonify({"message": "La solicitud a Spotify ha tardado demasiado. Por favor, intenta nuevamente más tarde."}), 504
        except spotipy.exceptions.SpotifyException as e:
            print(f"[ERROR] SpotifyException: {e}")
            return jsonify({"message": f"Error con la API de Spotify: {e.msg}"}), e.http_status

    except Exception as e:
        print(f"[ERROR] Error general en /top_artists_global: {e}")
        return jsonify({"message": f"Error interno: {str(e)}"}), 500

    return jsonify({"message": "Endpoint no encontrado."}), 404


@app.route('/videos', methods=['GET'])
def get_videos():
    youtube_url = "https://www.googleapis.com/youtube/v3/search"

    params = {
        "part": "snippet",
        "q": "music",
        "type": "video",
        "videoCategoryId": "10",
        "regionCode": "US",
        "maxResults": 10,
        "key": YOUTUBE_API_KEY
    }

    try:
        response = requests.get(youtube_url, params=params)
        response.raise_for_status()  

        videos = response.json().get("items", [])
        formatted_videos = [
            {
                "title": video['snippet']['title'],
                "channel": video['snippet']['channelTitle'],
                "thumbnail": video['snippet']['thumbnails']['high']['url'],
                "videoId": video['id']['videoId'],
                "url": f"https://www.youtube.com/watch?v={video['id']['videoId']}"
            }
            for video in videos
        ]
        return jsonify({"videos": formatted_videos}), 200

    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
        print(f"Response Content: {response.text}")
        return jsonify({"error": "Error al obtener los videos", "details": response.text}), response.status_code
    except requests.exceptions.RequestException as err:
        print(f"Error: {err}")
        return jsonify({"error": "Error al obtener los videos"}), 500


@app.route('/song_details', methods=['GET'])
@jwt_required()
def song_details():
    song_id = request.args.get('song_id')
    if not song_id:
        return jsonify({"message": "Se requiere el ID de la canción."}), 400

    current_user_email = get_jwt_identity()
    access_token = get_valid_spotify_token(current_user_email, mongo)
    if not access_token:
        return jsonify({"message": "Por favor, inicia sesión en Spotify."}), 401

    try:
        sp = spotipy.Spotify(auth=access_token)
        track = sp.track(song_id)

        song_info = {
            "id": track['id'],
            "name": track['name'],
            "artists": [artist['name'] for artist in track['artists']],
            "artist_ids": [artist['id'] for artist in track['artists']],
            "album": track['album']['name'],
            "album_id": track['album']['id'],
            "cover_image": track['album']['images'][0]['url'] if track['album']['images'] else None,
            "duration_ms": track['duration_ms'],
            "popularity": track['popularity'],
            "preview_url": track['preview_url'],
            "url": track['external_urls']['spotify'],
            "release_date": track['album']['release_date'],
        }

        # Obtener detalles adicionales de los artistas
        artist_ids = song_info['artist_ids']
        artists = sp.artists(artist_ids)['artists']
        genres = []
        followers = 0
        for artist in artists:
            genres.extend(artist['genres'])
            followers += artist['followers']['total']
        song_info['genres'] = genres
        song_info['followers'] = followers

        # Calcular averageRating y ratingCount desde la colección 'rates'
        pipeline = [
            {'$match': {'entityType': 'song', 'entityId': song_id}},
            {'$group': {
                '_id': None,
                'averageRating': {'$avg': '$rating'},
                'ratingCount': {'$sum': 1}
            }}
        ]
        agg_result = list(mongo.db.rates.aggregate(pipeline))
        if agg_result:
            average_rating = agg_result[0]['averageRating']
            rating_count = agg_result[0]['ratingCount']
        else:
            average_rating = 0
            rating_count = 0

        song_info['averageRating'] = average_rating
        song_info['ratingCount'] = rating_count

        logger.info(f"Detalles de la canción {song_id} con averageRating={average_rating} y ratingCount={rating_count}")

        return jsonify({'song': song_info}), 200

    except spotipy.exceptions.SpotifyException as e:
        return jsonify({"message": f"Error con la API de Spotify: {e.msg}"}), e.http_status
    except Exception as e:
        return jsonify({"message": f"Error al obtener los detalles de la canción: {str(e)}"}), 500


@app.route('/album_details', methods=['GET'])
@jwt_required()
def album_details():
    album_id = request.args.get('album_id')
    if not album_id:
        return jsonify({"message": "Se requiere el ID del álbum."}), 400

    current_user_email = get_jwt_identity()
    access_token = get_valid_spotify_token(current_user_email, mongo)
    if not access_token:
        return jsonify({"message": "Por favor, inicia sesión en Spotify."}), 401

    try:
        sp = spotipy.Spotify(auth=access_token)
        album = sp.album(album_id)

        album_info = {
            "id": album['id'],
            "name": album['name'],
            "artists": [artist['name'] for artist in album['artists']],
            "artist_ids": [artist['id'] for artist in album['artists']],  
            "cover_image": album['images'][0]['url'] if album['images'] else None,
            "release_date": album['release_date'],
            "total_tracks": album['total_tracks'],
            "url": album['external_urls']['spotify'],
            "tracks": []
        }

        for track in album['tracks']['items']:
            track_info = {
                "id": track['id'],
                "name": track['name'],
                "duration_ms": track['duration_ms'],
                "preview_url": track['preview_url'],
                "url": track['external_urls']['spotify'],
                "track_number": track['track_number'],
                "artists": [artist['name'] for artist in track['artists']],
                "artist_ids": [artist['id'] for artist in track['artists']], 
            }
            album_info['tracks'].append(track_info)

        # Calcular averageRating y ratingCount desde la colección 'rates'
        pipeline = [
            {'$match': {'entityType': 'album', 'entityId': album_id}},
            {'$group': {
                '_id': None,
                'averageRating': {'$avg': '$rating'},
                'ratingCount': {'$sum': 1}
            }}
        ]
        agg_result = list(mongo.db.rates.aggregate(pipeline))
        if agg_result:
            average_rating = agg_result[0]['averageRating']
            rating_count = agg_result[0]['ratingCount']
        else:
            average_rating = 0
            rating_count = 0

        album_info['averageRating'] = average_rating
        album_info['ratingCount'] = rating_count

        logger.info(f"Detalles del álbum {album_id} con averageRating={average_rating} y ratingCount={rating_count}")

        return jsonify({'album': album_info}), 200

    except spotipy.exceptions.SpotifyException as e:
        return jsonify({"message": f"Error con la API de Spotify: {e.msg}"}), e.http_status
    except Exception as e:
        return jsonify({"message": f"Error al obtener los detalles del álbum: {str(e)}"}), 500


@app.route('/artist_details', methods=['GET'])
@jwt_required()
def artist_details():
    artist_id = request.args.get('artist_id')
    if not artist_id:
        return jsonify({"message": "Se requiere el ID del artista."}), 400

    current_user_email = get_jwt_identity()
    access_token = get_valid_spotify_token(current_user_email, mongo)
    if not access_token:
        return jsonify({"message": "Por favor, inicia sesión en Spotify."}), 401

    try:
        sp = spotipy.Spotify(auth=access_token)
        artist = sp.artist(artist_id)
        albums = sp.artist_albums(artist_id, album_type='album')['items']

        artist_info = {
            'id': artist['id'],
            'name': artist['name'],
            'image': artist['images'][0]['url'] if artist['images'] else None,
            'genres': artist['genres'],
            'popularity': artist['popularity'],
            'followers': artist['followers']['total'],
        }

        albums_info = []
        for album in albums:
            albums_info.append({
                'id': album['id'],
                'title': album['name'],
                'image': album['images'][0]['url'] if album['images'] else None,
                'release_date': album['release_date'],
            })

        pipeline = [
            {'$match': {'entityType': 'artist', 'entityId': artist_id}},
            {'$group': {
                '_id': None,
                'averageRating': {'$avg': '$rating'},
                'ratingCount': {'$sum': 1}
            }}
        ]
        agg_result = list(mongo.db.rates.aggregate(pipeline))
        if agg_result:
            average_rating = agg_result[0]['averageRating']
            rating_count = agg_result[0]['ratingCount']
        else:
            average_rating = 0
            rating_count = 0

        artist_info['averageRating'] = average_rating
        artist_info['ratingCount'] = rating_count

        logger.info(f"Detalles del artista {artist_id} con averageRating={average_rating} y ratingCount={rating_count}")

        return jsonify({'artist': artist_info, 'albums': albums_info}), 200

    except spotipy.exceptions.SpotifyException as e:
        return jsonify({"message": f"Error con la API de Spotify: {e.msg}"}), e.http_status
    except Exception as e:
        return jsonify({"message": f"Error al obtener los detalles del artista: {str(e)}"}), 500
    

@app.route('/profile_details', methods=['GET'])
def get_profile_details():
    profile_id = request.args.get('profile_id')
    if not profile_id:
        return jsonify({"message": "Se requiere profile_id"}), 400

    try:
        from bson.objectid import ObjectId
        user = mongo.db.users.find_one({"_id": ObjectId(profile_id)})
        if not user:
            return jsonify({"message": "Perfil no encontrado"}), 404

        # Devuelve datos del usuario similares a los del profile actual
        profile_data = {
            "id": str(user['_id']),
            "username": user.get('username', ''),
            "email": user.get('email', ''),
            "profile_picture": user.get('profile_picture', ''), 
            "favorites": user.get('favorites', []),
            "comments_enabled": True 
        }
        return jsonify(profile_data), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 500




@app.route('/album_tracks', methods=['GET'])
@jwt_required()
def get_album_tracks():
    album_id = request.args.get('album_id')
    if not album_id:
        return jsonify({"message": "Se requiere el ID del álbum."}), 400

    current_user = get_jwt_identity()

    access_token = get_valid_spotify_token(current_user, mongo)
    if not access_token:
        return jsonify({"message": "Por favor, inicia sesión en Spotify para ver las canciones del álbum."}), 401

    try:
        sp = spotipy.Spotify(auth=access_token)

        album_tracks_results = sp.album_tracks(album_id)
        
        # Formatear las canciones del álbum
        tracks = []
        for item in album_tracks_results['items']:
            track_info = {
                "name": item['name'],
                "track_number": item['track_number'],
                "duration_ms": item['duration_ms'],
                "preview_url": item.get('preview_url'),
                "url": item['external_urls']['spotify']
            }
            tracks.append(track_info)

        return jsonify({"tracks": tracks}), 200

    except Exception as e:
        return jsonify({"message": f"Error al obtener las canciones del álbum: {str(e)}"}), 500


# ------------------------------ Rutas de Comentarios ----------------------------------------

@app.route('/<entity_type>/<entity_id>/comments', methods=['POST'])
@jwt_required()
def add_comment(entity_type, entity_id):
    try:
        # Validar entity_type
        valid_entity_types = ['profile', 'song', 'album', 'artist']
        if entity_type not in valid_entity_types:
            return jsonify({"message": f"Tipo de entidad inválido. Debe ser uno de {valid_entity_types}."}), 400

        current_user_email = get_jwt_identity()
        user = mongo.db.users.find_one({'email': current_user_email})
        if not user:
            return jsonify({"message": "Usuario no encontrado."}), 404

        user_id = str(user['_id'])  # Convertir ObjectId a string
        username = user['username']
        user_photo = user.get('profile_picture', "")
        user_email = user.get('email', "")

        # Obtener y validar el texto del comentario
        data = request.get_json()
        comment_text = data.get('comment_text', '').strip()

        if not comment_text:
            return jsonify({"message": "El texto del comentario no puede estar vacío."}), 400

        if entity_type == 'profile':
            try:
                entity_obj_id = ObjectId(entity_id)
                # Verificar que el perfil existe en MongoDB
                profile = mongo.db.users.find_one({'_id': entity_obj_id})
                if not profile:
                    return jsonify({"message": "Perfil no encontrado."}), 404
            except InvalidId:
                return jsonify({"message": "ID de entidad inválido."}), 400
        else:
            # Verificar la existencia de la entidad en Spotify
            access_token = get_valid_spotify_token(current_user_email, mongo)
            if not access_token:
                return jsonify({"message": "Por favor, inicia sesión en Spotify."}), 401
            sp = spotipy.Spotify(auth=access_token)
            entity_exists = verify_entity_exists(entity_type, entity_id, sp)
            if not entity_exists:
                return jsonify({"message": f"{entity_type.capitalize()} no encontrado."}), 404
            entity_obj_id = entity_id  # Mantener el entity_id como cadena

        # Crear el documento de comentario
        comment = {
            "entity_type": entity_type,
            "entity_id": entity_obj_id,
            "user_id": user_id,
            "username": username,
            "user_photo": user_photo,
            "user_email": user_email,
            "comment_text": comment_text,
            "timestamp": datetime.now(timezone.utc),
            "likes": 0,
            "dislikes": 0,
            "liked_by": [],
            "disliked_by": []
        }

        result = mongo.db.comments.insert_one(comment)

        inserted_comment = mongo.db.comments.find_one({"_id": result.inserted_id})
        inserted_comment['_id'] = str(inserted_comment['_id'])
        inserted_comment['entity_id'] = str(inserted_comment['entity_id']) if entity_type == 'profile' else inserted_comment['entity_id']
        inserted_comment['user_id'] = inserted_comment['user_id']
        inserted_comment['timestamp'] = inserted_comment['timestamp'].isoformat()

        return jsonify({"message": "Comentario agregado exitosamente.", "comment": inserted_comment}), 201

    except Exception as e:
        return jsonify({"message": f"Error al agregar el comentario: {str(e)}"}), 500


@app.route('/<entity_type>/<entity_id>/comments/<comment_id>', methods=['DELETE'])
@jwt_required()
def delete_comment(entity_type, entity_id, comment_id):
    try:
        valid_entity_types = ['profile', 'song', 'album', 'artist']
        if entity_type not in valid_entity_types:
            return jsonify({"message": f"Tipo de entidad inválido. Debe ser uno de {valid_entity_types}."}), 400

        current_user_email = get_jwt_identity()
        user = mongo.db.users.find_one({'email': current_user_email})
        if not user:
            return jsonify({"message": "Usuario no encontrado."}), 404

        user_id = str(user['_id'])  

        if entity_type == 'profile':
            try:
                entity_obj_id = ObjectId(entity_id)
                profile = mongo.db.users.find_one({'_id': entity_obj_id})
                if not profile:
                    return jsonify({"message": "Perfil no encontrado."}), 404
            except InvalidId:
                return jsonify({"message": "ID de entidad inválido."}), 400
        else:
            access_token = get_valid_spotify_token(current_user_email, mongo)
            if not access_token:
                return jsonify({"message": "Por favor, inicia sesión en Spotify."}), 401
            sp = spotipy.Spotify(auth=access_token)
            entity_exists = verify_entity_exists(entity_type, entity_id, sp)
            if not entity_exists:
                return jsonify({"message": f"{entity_type.capitalize()} no encontrado."}), 404
            entity_obj_id = entity_id

        comment = mongo.db.comments.find_one({
            "_id": ObjectId(comment_id),
            "entity_type": entity_type,
            "entity_id": entity_obj_id
        })

        if not comment:
            return jsonify({"message": "Comentario no encontrado."}), 404

        # Verificar que el usuario actual es el propietario del comentario
        if comment['user_id'] != user_id:
            return jsonify({"message": "No tienes permiso para eliminar este comentario."}), 403

        # Eliminar el comentario
        mongo.db.comments.delete_one({"_id": ObjectId(comment_id)})

        return jsonify({"message": "Comentario eliminado exitosamente."}), 200

    except Exception as e:
        return jsonify({"message": f"Error al eliminar el comentario: {str(e)}"}), 500


@app.route('/<entity_type>/<entity_id>/comments', methods=['GET'])
@jwt_required()
def get_comments(entity_type, entity_id):
    try:
        app.logger.info(f"Solicitud para obtener comentarios: entity_type={entity_type}, entity_id={entity_id}")

        valid_entity_types = ['profile', 'song', 'album', 'artist']
        if entity_type not in valid_entity_types:
            app.logger.warning(f"Tipo de entidad inválido: {entity_type}")
            return jsonify({"message": f"Tipo de entidad inválido. Debe ser uno de {valid_entity_types}."}), 400

        if entity_type == 'profile':
            try:
                entity_obj_id = ObjectId(entity_id)
                profile = mongo.db.users.find_one({'_id': entity_obj_id})
                if not profile:
                    app.logger.warning(f"Perfil no encontrado: {entity_id}")
                    return jsonify({"message": "Perfil no encontrado."}), 404
            except InvalidId:
                app.logger.warning(f"ID de entidad inválido: {entity_id}")
                return jsonify({"message": "ID de entidad inválido."}), 400
        else:
            current_user_email = get_jwt_identity()
            access_token = get_valid_spotify_token(current_user_email, mongo)
            if not access_token:
                app.logger.error("Token de acceso a Spotify no disponible.")
                return jsonify({"message": "Por favor, inicia sesión en Spotify."}), 401
            sp = spotipy.Spotify(auth=access_token)
            entity_exists = verify_entity_exists(entity_type, entity_id, sp)
            if not entity_exists:
                app.logger.warning(f"{entity_type.capitalize()} no encontrado: {entity_id}")
                return jsonify({"message": f"{entity_type.capitalize()} no encontrado."}), 404
            entity_obj_id = entity_id

        try:
            page = int(request.args.get('page', 1))
            limit = int(request.args.get('limit', 10))
            if limit > 100:
                limit = 100  
        except ValueError:
            app.logger.warning("Parámetros de paginación inválidos.")
            return jsonify({"message": "Los parámetros 'page' y 'limit' deben ser números enteros."}), 400

        skip = (page - 1) * limit

        comments_cursor = mongo.db.comments.find(
            {"entity_type": entity_type, "entity_id": entity_obj_id}
        ).sort([("likes", -1), ("timestamp", -1)]).skip(skip).limit(limit)

        comments = []
        for comment in comments_cursor:
            try:
                comment['_id'] = str(comment['_id'])
                if entity_type == 'profile':
                    comment['entity_id'] = str(comment['entity_id'])
                comment['user_id'] = str(comment['user_id'])

                if isinstance(comment.get('timestamp'), datetime):
                    comment['timestamp'] = comment['timestamp'].isoformat()
                else:
                    try:
                        comment['timestamp'] = datetime.fromisoformat(comment['timestamp']).isoformat()
                    except (ValueError, TypeError):
                        comment['timestamp'] = "Desconocido"

                comment['likes'] = int(comment.get('likes', 0))
                comment['dislikes'] = int(comment.get('dislikes', 0))
                
                # Convertir cada ObjectId en 'liked_by' y 'disliked_by' a string
                liked_by = comment.get('liked_by', [])
                if isinstance(liked_by, list):
                    comment['liked_by'] = [str(uid) for uid in liked_by]
                else:
                    comment['liked_by'] = []

                disliked_by = comment.get('disliked_by', [])
                if isinstance(disliked_by, list):
                    comment['disliked_by'] = [str(uid) for uid in disliked_by]
                else:
                    comment['disliked_by'] = []

                comments.append(comment)
            except Exception as e:
                app.logger.error(f"Error al procesar el comentario {comment.get('_id')}: {str(e)}")
                return jsonify({"message": f"Error al procesar un comentario: {str(e)}"}), 500

        # Obtener el total de comentarios para calcular el número de páginas
        total_comments = mongo.db.comments.count_documents({
            "entity_type": entity_type,
            "entity_id": entity_obj_id
        })

        total_pages = (total_comments + limit - 1) // limit

        app.logger.info(f"Comentarios obtenidos: {len(comments)} para la página {page}")

        return jsonify({
            "comments": comments,
            "pagination": {
                "total_comments": total_comments,
                "total_pages": total_pages,
                "current_page": page
            }
        }), 200

    except Exception as e:
        app.logger.error(f"Error al obtener los comentarios: {str(e)}")
        return jsonify({"message": f"Error al obtener los comentarios: {str(e)}"}), 500

# ------------------------------------ Likes -------------------------------------------------

# Ruta para dar "like" a un comentario
@app.route('/<entity_type>/<entity_id>/comments/<comment_id>/like', methods=['POST'])
@jwt_required()
def like_comment(entity_type, entity_id, comment_id):
    try:
        current_user_email = get_jwt_identity()
        user = mongo.db.users.find_one({'email': current_user_email})
        if not user:
            return jsonify({"message": "Usuario no encontrado."}), 404
        user_id = str(user['_id'])  

        valid_entity_types = ['profile', 'song', 'album', 'artist']
        if entity_type not in valid_entity_types:
            return jsonify({"message": f"Tipo de entidad inválido. Debe ser uno de {valid_entity_types}."}), 400

        if entity_type == 'profile':
            try:
                entity_obj_id = ObjectId(entity_id)
                profile = mongo.db.users.find_one({'_id': entity_obj_id})
                if not profile:
                    return jsonify({"message": "Perfil no encontrado."}), 404
            except InvalidId:
                return jsonify({"message": "ID de entidad inválido."}), 400
        else:
            access_token = get_valid_spotify_token(current_user_email, mongo)
            if not access_token:
                return jsonify({"message": "Por favor, inicia sesión en Spotify."}), 401
            sp = spotipy.Spotify(auth=access_token)
            entity_exists = verify_entity_exists(entity_type, entity_id, sp)
            if not entity_exists:
                return jsonify({"message": f"{entity_type.capitalize()} no encontrado."}), 404
            entity_obj_id = entity_id

        # Buscar el comentario
        comment = mongo.db.comments.find_one({'_id': ObjectId(comment_id), 'entity_type': entity_type, 'entity_id': entity_obj_id})
        if not comment:
            return jsonify({"message": "Comentario no encontrado."}), 404

        # Lógica para "like"
        liked_by = comment.get('liked_by', [])
        disliked_by = comment.get('disliked_by', [])

        if user_id in liked_by:
            # Si el usuario ya ha dado like, lo elimina
            mongo.db.comments.update_one(
                {'_id': ObjectId(comment_id)},
                {
                    '$inc': {'likes': -1},
                    '$pull': {'liked_by': user_id}
                }
            )
            liked = False
        else:
            # Agrega el like y elimina el dislike si existía
            update_fields = {
                '$inc': {'likes': 1},
                '$addToSet': {'liked_by': user_id},
                '$pull': {'disliked_by': user_id}
            }
            # Si el usuario había dado dislike previamente, decrementa dislikes
            if user_id in disliked_by:
                update_fields['$inc']['dislikes'] = -1
            mongo.db.comments.update_one(
                {'_id': ObjectId(comment_id)},
                update_fields
            )
            liked = True

        # Obtener el comentario actualizado
        updated_comment = mongo.db.comments.find_one({'_id': ObjectId(comment_id)})
        updated_comment['_id'] = str(updated_comment['_id'])
        updated_comment['entity_id'] = str(updated_comment['entity_id']) if entity_type == 'profile' else updated_comment['entity_id']
        updated_comment['user_id'] = str(updated_comment['user_id'])
        updated_comment['timestamp'] = updated_comment['timestamp'].isoformat()
        updated_comment['liked_by'] = updated_comment.get('liked_by', [])
        updated_comment['disliked_by'] = updated_comment.get('disliked_by', [])

        return jsonify({"message": "Like actualizado.", "comment": updated_comment, "liked": liked}), 200

    except Exception as e:
        app.logger.error(f"Error en like_comment: {e}")
        return jsonify({"message": f"Error al procesar el like: {str(e)}"}), 500


@app.route('/<entity_type>/<entity_id>/comments/<comment_id>/dislike', methods=['POST'])
@jwt_required()
def dislike_comment(entity_type, entity_id, comment_id):
    try:
        # Obtener el email del usuario desde el JWT
        current_user_email = get_jwt_identity()
        user = mongo.db.users.find_one({'email': current_user_email})
        if not user:
            return jsonify({"message": "Usuario no encontrado."}), 404
        user_id = str(user['_id'])  # Convertir ObjectId a string

        # Validar entity_type
        valid_entity_types = ['profile', 'song', 'album', 'artist']
        if entity_type not in valid_entity_types:
            return jsonify({"message": f"Tipo de entidad inválido. Debe ser uno de {valid_entity_types}."}), 400

        if entity_type == 'profile':
            try:
                entity_obj_id = ObjectId(entity_id)
                profile = mongo.db.users.find_one({'_id': entity_obj_id})
                if not profile:
                    return jsonify({"message": "Perfil no encontrado."}), 404
            except InvalidId:
                return jsonify({"message": "ID de entidad inválido."}), 400
        else:
            # Verificar la existencia de la entidad en Spotify
            access_token = get_valid_spotify_token(current_user_email, mongo)
            if not access_token:
                return jsonify({"message": "Por favor, inicia sesión en Spotify."}), 401
            sp = spotipy.Spotify(auth=access_token)
            entity_exists = verify_entity_exists(entity_type, entity_id, sp)
            if not entity_exists:
                return jsonify({"message": f"{entity_type.capitalize()} no encontrado."}), 404
            entity_obj_id = entity_id

        # Buscar el comentario
        comment = mongo.db.comments.find_one({'_id': ObjectId(comment_id), 'entity_type': entity_type, 'entity_id': entity_obj_id})
        if not comment:
            return jsonify({"message": "Comentario no encontrado."}), 404

        # Lógica para "dislike"
        liked_by = comment.get('liked_by', [])
        disliked_by = comment.get('disliked_by', [])

        if user_id in disliked_by:
            # Si el usuario ya ha dado dislike, lo elimina
            mongo.db.comments.update_one(
                {'_id': ObjectId(comment_id)},
                {
                    '$inc': {'dislikes': -1},
                    '$pull': {'disliked_by': user_id}
                }
            )
            disliked = False
        else:
            # Agrega el dislike y elimina el like si existía
            update_fields = {
                '$inc': {'dislikes': 1},
                '$addToSet': {'disliked_by': user_id},
                '$pull': {'liked_by': user_id}
            }
            # Si el usuario había dado like previamente, decrementa likes
            if user_id in liked_by:
                update_fields['$inc']['likes'] = -1
            mongo.db.comments.update_one(
                {'_id': ObjectId(comment_id)},
                update_fields
            )
            disliked = True

        # Obtener el comentario actualizado
        updated_comment = mongo.db.comments.find_one({'_id': ObjectId(comment_id)})
        updated_comment['_id'] = str(updated_comment['_id'])
        updated_comment['entity_id'] = str(updated_comment['entity_id']) if entity_type == 'profile' else updated_comment['entity_id']
        updated_comment['user_id'] = str(updated_comment['user_id'])
        updated_comment['timestamp'] = updated_comment['timestamp'].isoformat()
        updated_comment['liked_by'] = updated_comment.get('liked_by', [])
        updated_comment['disliked_by'] = updated_comment.get('disliked_by', [])

        return jsonify({"message": "Dislike actualizado.", "comment": updated_comment, "disliked": disliked}), 200

    except Exception as e:
        app.logger.error(f"Error en dislike_comment: {e}")
        return jsonify({"message": f"Error al procesar el dislike: {str(e)}"}), 500


#------------------------------------ Favoritos ----------------------

@app.route('/add_favorite', methods=['POST'])
@jwt_required()
def add_favorite():
    data = request.get_json()
    entity_type = data.get('entityType')
    entity_id = data.get('entityId')
    name = data.get('name')
    image = data.get('image')

    if not all([entity_type, entity_id]):
        return jsonify({"message": "Se requiere entityType y entityId."}), 400

    current_user_email = get_jwt_identity()
    user = mongo.db.users.find_one({'email': current_user_email})

    existing_favorite = next((fav for fav in user.get('favorites', []) if fav['entityId'] == entity_id), None)
    if existing_favorite:
        return jsonify({"message": "El favorito ya existe."}), 400

    new_favorite = {
        'entityType': entity_type,
        'entityId': entity_id,
        'name': name,
        'image': image,
    }

    mongo.db.users.update_one(
        {'email': current_user_email},
        {'$push': {'favorites': new_favorite}}
    )

    return jsonify({"message": "Favorito agregado exitosamente."}), 200


@app.route('/remove_favorite', methods=['POST'])
@jwt_required()
def remove_favorite():
    data = request.get_json()
    entity_id = data.get('entityId')

    if not entity_id:
        return jsonify({"message": "Se requiere entityId."}), 400

    current_user_email = get_jwt_identity()

    mongo.db.users.update_one(
        {'email': current_user_email},
        {'$pull': {'favorites': {'entityId': entity_id}}}
    )

    return jsonify({"message": "Favorito eliminado exitosamente."}), 200


@app.route('/get_favorites', methods=['GET'])
@jwt_required()
def get_favorites():
    current_user_email = get_jwt_identity()
    user = mongo.db.users.find_one({'email': current_user_email})

    favorites = user.get('favorites', [])

    return jsonify({'favorites': favorites}), 200



@app.route('/recently_listened', methods=['GET'])
@jwt_required()
def recently_listened():
    user_email = get_jwt_identity()
    access_token = get_valid_spotify_token(user_email, mongo)
    if not access_token:
        return jsonify({'error': 'No se pudo obtener el token de Spotify.'}), 500

    sp = spotipy.Spotify(auth=access_token)
    try:
        recently_played = sp.current_user_recently_played(limit=10)
        songs = []  
        for item in recently_played['items']:
            track = item['track']
            songs.append({
                'id': track['id'],  
                'name': track['name'],
                'artist': ', '.join([artist['name'] for artist in track['artists']]),
                'album': track['album']['name'],
                'cover_image': track['album']['images'][0]['url'] if track['album']['images'] else None,
                'url': track['external_urls']['spotify'],
            })
        return jsonify({'songs': songs}), 200
    except Exception as e:
        return jsonify({'error': f'Error al obtener canciones reproducidas recientemente: {str(e)}'}), 500


#----------------------------- Rating ----------------------

@app.route('/rate_entity', methods=['POST'])
@jwt_required()
def rate_entity():
    data = request.get_json()
    entity_type = data.get('entityType') 
    entity_id = data.get('entityId')
    rating = data.get('rating')  # Número entre 1 y 10

    logger.info(f"Received rate_entity request: entity_type={entity_type}, entity_id={entity_id}, rating={rating}")

    if not entity_type or not entity_id or rating is None:
        logger.warning("Missing fields in rate_entity request.")
        return jsonify({'message': 'Todos los campos son obligatorios.'}), 400

    if entity_type not in ['song', 'album', 'artist']:
        logger.warning(f"Invalid entityType: {entity_type}")
        return jsonify({'message': 'Tipo de entidad inválido.'}), 400

    if not isinstance(rating, int) or not (1 <= rating <= 10):
        logger.warning(f"Invalid rating: {rating}")
        return jsonify({'message': 'La calificación debe ser un número entre 1 y 10.'}), 400

    user_email = get_jwt_identity()
    user = mongo.db.users.find_one({'email': user_email})
    if not user:
        logger.warning(f"User not found: {user_email}")
        return jsonify({'message': 'Usuario no encontrado.'}), 404

    user_id = user['_id']
    try:
        # Verificar si el usuario ya ha calificado esta entidad
        existing_rating = mongo.db.rates.find_one({
            'entityType': entity_type,
            'entityId': entity_id,
            'userId': user_id
        })

        if existing_rating:
            logger.info(f"Usuario {user_email} ya ha calificado la entidad {entity_id}")
            return jsonify({'message': 'Ya has calificado esta entidad.'}), 400

        # Añadir la calificación
        new_rate = {
            'entityType': entity_type,
            'entityId': entity_id,
            'userId': user_id,
            'rating': rating,
            'timestamp': datetime.utcnow()
        }
        mongo.db.rates.insert_one(new_rate)
        logger.info(f"Calificación añadida por {user_email} a {entity_type} {entity_id}")

        # Calcular el nuevo promedio y conteo de calificaciones
        pipeline = [
            {'$match': {'entityType': entity_type, 'entityId': entity_id}},
            {'$group': {'_id': None, 'averageRating': {'$avg': '$rating'}, 'ratingCount': {'$sum': 1}}}
        ]
        agg_result = list(mongo.db.rates.aggregate(pipeline))
        if agg_result:
            avg = agg_result[0]['averageRating']
            count = agg_result[0]['ratingCount']
            logger.info(f"Entidad {entity_id} calculada con averageRating={avg}, ratingCount={count}")
            return jsonify({'message': 'Calificación añadida correctamente.', 'averageRating': avg, 'ratingCount': count}), 201
        else:
            logger.info(f"Entidad {entity_id} calculada con averageRating={rating}, ratingCount=1")
            return jsonify({'message': 'Calificación añadida correctamente.', 'averageRating': rating, 'ratingCount': 1}), 201

    except Exception as e:
        logger.error(f"Error al añadir calificación: {e}")
        return jsonify({'message': 'Error interno del servidor.'}), 500
   
  

@app.route('/get_user_rating', methods=['GET'])
@jwt_required()
def get_user_rating():
    entity_type = request.args.get('entityType')  
    entity_id = request.args.get('entityId')

    logger.info(f"Solicitud para obtener calificación: entity_type={entity_type}, entity_id={entity_id}")

    if not entity_type or not entity_id:
        logger.warning("Missing parameters in get_user_rating request.")
        return jsonify({'message': 'Todos los parámetros son obligatorios.'}), 400

    if entity_type not in ['song', 'album', 'artist']:
        logger.warning(f"Invalid entityType: {entity_type}")
        return jsonify({'message': 'Tipo de entidad inválido.'}), 400

    user_email = get_jwt_identity()
    user = mongo.db.users.find_one({'email': user_email})
    if not user:
        logger.warning(f"User not found: {user_email}")
        return jsonify({'message': 'Usuario no encontrado.'}), 404

    user_id = user['_id']

    try:
        existing_rating = mongo.db.rates.find_one({
            'entityType': entity_type,
            'entityId': entity_id,
            'userId': user_id
        })

        if existing_rating:
            logger.info(f"Calificación encontrada: {existing_rating['rating']}")
            return jsonify({'rating': existing_rating['rating']}), 200
        else:
            logger.info("No se encontró calificación existente.")
            return jsonify({'rating': 0}), 200

    except Exception as e:
        logger.error(f"Error al obtener calificación del usuario: {e}")
        return jsonify({'message': 'Error interno del servidor.'}), 500


@app.route('/follow_user', methods=['POST'])
@jwt_required()
def follow_user():
    current_user_email = get_jwt_identity()
    current_user = mongo.db.users.find_one({"email": current_user_email})
    if not current_user:
        return jsonify({"message": "Usuario no encontrado"}), 404

    data = request.get_json()
    profile_id = data.get("profile_id")
    if not profile_id:
        return jsonify({"message": "Se requiere profile_id"}), 400

    # Verificar que el usuario a seguir existe
    from bson.objectid import ObjectId
    try:
        target_user = mongo.db.users.find_one({"_id": ObjectId(profile_id)})
        if not target_user:
            return jsonify({"message": "Perfil no encontrado"}), 404
    except:
        return jsonify({"message": "profile_id inválido"}), 400

    current_user_id = current_user["_id"]

    # Añadir el current_user a los followers del target
    mongo.db.users.update_one(
        {"_id": target_user["_id"]},
        {"$addToSet": {"followers": str(current_user_id)}}
    )

    # Añadir el target a los following del current_user
    mongo.db.users.update_one(
        {"_id": current_user_id},
        {"$addToSet": {"following": str(target_user["_id"])}}
    )

    return jsonify({"message": "Usuario seguido exitosamente"}), 200


@app.route('/unfollow_user', methods=['POST'])
@jwt_required()
def unfollow_user():
    current_user_email = get_jwt_identity()
    current_user = mongo.db.users.find_one({"email": current_user_email})
    if not current_user:
        return jsonify({"message": "Usuario no encontrado"}), 404

    data = request.get_json()
    profile_id = data.get("profile_id")
    if not profile_id:
        return jsonify({"message": "Se requiere profile_id"}), 400

    from bson.objectid import ObjectId
    try:
        target_user = mongo.db.users.find_one({"_id": ObjectId(profile_id)})
        if not target_user:
            return jsonify({"message": "Perfil no encontrado"}), 404
    except:
        return jsonify({"message": "profile_id inválido"}), 400

    current_user_id = current_user["_id"]

    # Remover current_user de los followers del target
    mongo.db.users.update_one(
        {"_id": target_user["_id"]},
        {"$pull": {"followers": str(current_user_id)}}
    )

    # Remover target de los following del current_user
    mongo.db.users.update_one(
        {"_id": current_user_id},
        {"$pull": {"following": str(target_user["_id"])}}
    )

    return jsonify({"message": "Usuario dejado de seguir exitosamente"}), 200

@app.route('/get_following_details', methods=['POST'])
@jwt_required()
def get_following_details():
    current_user_email = get_jwt_identity()
    current_user = mongo.db.users.find_one({"email": current_user_email})
    if not current_user:
        return jsonify({"message": "Usuario no encontrado"}), 404

    data = request.get_json()
    ids = data.get("ids", [])
    if not isinstance(ids, list):
        return jsonify({"message": "El campo 'ids' debe ser una lista."}), 400

    from bson.objectid import ObjectId

    # Convertir los IDs en ObjectId y filtrar aquellos que no sean válidos
    object_ids = []
    for uid in ids:
        try:
            obj_id = ObjectId(uid)
            object_ids.append(obj_id)
        except:
            # Si el ID no es un ObjectId válido, se ignora o podrías retornar un error
            pass

    if not object_ids:
        return jsonify({"users": []}), 200

    # Buscar todos los usuarios cuyos _id estén en la lista object_ids
    found_users = list(mongo.db.users.find({"_id": {"$in": object_ids}}))

    # Preparar la respuesta con los datos relevantes
    # Ajusta los campos según las necesidades del frontend
    users_list = []
    for u in found_users:
        users_list.append({
            "id": str(u["_id"]),
            "username": u.get("username", ""),
            "profile_picture": u.get("profile_picture", ""),  
            # Agrega otros campos si lo deseas, como 'email' o 'favorites'
        })

    return jsonify({"users": users_list}), 200



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
