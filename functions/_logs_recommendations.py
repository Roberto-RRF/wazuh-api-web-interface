import matplotlib.pyplot as plt
from kneed import KneeLocator
from sklearn.decomposition import PCA
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
import numpy as np
from openai import OpenAI

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'txt'}

def read_and_prepare_logs(path):
    try:
        with open(path, 'r', encoding='utf-8') as file:
            logs = file.readlines()
        logs = [log.strip().lower() for log in logs]
        return logs
    except IOError as e:
        return str(e)

def calculate_optimal_clusters(logs, max_features=1000):
    vectorizer = TfidfVectorizer(max_features=max_features)
    X = vectorizer.fit_transform(logs)
    distortions = []
    K = range(1, 11)
    for k in K:
        kmeanModel = KMeans(n_clusters=k, n_init='auto', random_state=42)
        kmeanModel.fit(X)
        distortions.append(kmeanModel.inertia_)
    kn = KneeLocator(K, distortions, curve='convex', direction='decreasing')
    return kn.knee, vectorizer, X, distortions

def plot_elbow_method(K, distortions, k):
    plt.figure(figsize=(16,8))
    plt.plot(K, distortions, 'bx-')
    plt.xlabel('k')
    plt.ylabel('Distorsión')
    plt.title('El Método del Codo mostrando el número óptimo de clústeres')
    plt.vlines(k, plt.ylim()[0], plt.ylim()[1], linestyles='dashed')
    plt.grid(True)
    elbow_plot_path = "images/Numero_Clusters-Metodo_Codo.png"
    plt.savefig(f"static/{elbow_plot_path}")
    plt.close()
    return elbow_plot_path


def visualize_clusters(k, X, vectorizer):
    kmeans = KMeans(n_clusters=k, n_init='auto', random_state=42)
    kmeans.fit(X)
    labels = kmeans.labels_
    pca = PCA(n_components=2)
    X_pca = pca.fit_transform(np.asarray(X.todense()))
    plt.figure(figsize=(8, 6))
    for i in range(k):
        plt.scatter(X_pca[labels == i, 0], X_pca[labels == i, 1], label=f'Cluster {i+1}')
    plt.title('Visualización de Clusters de Logs')
    plt.xlabel('Componente Principal 1')
    plt.ylabel('Componente Principal 2')
    plt.legend()
    cluster_plot_path = 'images/Distribucion_Clusters.png'
    plt.savefig(f"static/{cluster_plot_path}")
    plt.close()
    return kmeans, labels, cluster_plot_path


def extract_keywords(kmeans, vectorizer, top_n=20):
    feature_names = vectorizer.get_feature_names_out()
    clusters_keywords = {}
    for i in range(kmeans.n_clusters):
        centroid = kmeans.cluster_centers_[i]
        top_features_indices = np.argsort(centroid)[-top_n:]
        top_features = [feature_names[j] for j in top_features_indices]
        clusters_keywords[f'cluster_{i+1}'] = top_features
    return clusters_keywords

def random_log_selection(labels, logs, k):
    clusters_samples = {}
    for i in range(k):
        cluster = np.where(labels == i)[0]
        if len(cluster) > 10:
            random_indices = np.random.choice(cluster, 10, replace=False)
        else:
            random_indices = cluster
        samples = [logs[idx] for idx in random_indices]
        clusters_samples[f'cluster_{i+1}'] = samples
    return clusters_samples

def process_file(path):
    logs = read_and_prepare_logs(path)
    if isinstance(logs, str):
        return logs  # Return error message if any

    k, vectorizer, X, distortions = calculate_optimal_clusters(logs)
    elbow_plot_path = plot_elbow_method(range(1, 11), distortions, k)
    kmeans, labels, cluster_plot_path = visualize_clusters(k, X, vectorizer)
    clusters_keywords = extract_keywords(kmeans, vectorizer)
    clusters_samples = random_log_selection(labels, logs, k)

    return {
        "optimal_clusters": k,
        "clusters_keywords": clusters_keywords,
        "clusters_samples": clusters_samples,
        "elbow_plot_path": elbow_plot_path,
        "cluster_plot_path": cluster_plot_path
    }

def clusteres_data(clusters_keywords,clusters_samples):
    user_message = "Aquí tienes la información de los clusters:\n\n"
    for i, (keywords, samples) in enumerate(zip(clusters_keywords.values(), clusters_samples.values()), 1):
        user_message += f"Cluster {i}:\nPalabras clave: {', '.join(keywords)}\n"
        user_message += "Logs de ejemplo:\n" + '\n'.join(samples) + "\n\n"
    return user_message

def openai_call(user_message):
    client = OpenAI(api_key="")
    response = client.chat.completions.create(
    model="gpt-3.5-turbo",
    messages=[
        {"role": "system", "content": "Eres un especialista en Ciberseguridad el cual tendra de input unas palabras claves y ejemplos de logs asociados a clusteres, basado en estos haras un reporte detallado y extenso con recomendaciones de que deberia extraer un decoder de Wazuh para cada cluster y las reglas que deberian escribirse, menciona en tu respuesta lo que ves en los logs"},
        {"role": "user", "content": user_message},
        ]
    )
    return response.choices[0].message.content