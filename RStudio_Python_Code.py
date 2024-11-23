# Get ddos report data
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.dates import DateFormatter
import networkx as nx
import plotly.graph_objects as go

reports_dir = "reports"
summary_stats_dir = f"{reports_dir}/summary_stats"
traffic_vol_dir = f"{reports_dir}/traffic_vol"

ddos = pd.read_csv(f"{traffic_vol_dir}/ddos_report.csv")

# Types & Data Cleaning
# timestamp           datetime64[ns]
# label                        Int64
# malware_name        string[python]
# orig_bytes                   Int64
# source_ip           string[python]
# source_port                  Int64
# destination_ip      string[python]
# destination_port             Int64
# conn_duration               object -> Int64
# conn_history        string[python]
ddos['timestamp'] = pd.to_datetime(ddos['timestamp'])
ddos['label'] = ddos['label'].str.strip().str.lower().map({'benign': 0, 'malicious': 1}).astype('Int64')
ddos['malware_name'] = ddos['malware_name'].astype('string')
ddos['orig_bytes'] = ddos['orig_bytes'].fillna(0).astype('Int64')
ddos['source_ip'] = ddos['source_ip'].astype('string')
ddos['source_port'] = ddos['source_port'].astype('Int64')
ddos['destination_ip'] = ddos['destination_ip'].astype('string')
ddos['destination_port'] = ddos['destination_port'].astype('Int64')
ddos['conn_duration'] = ddos['conn_duration'].replace('-', 0).fillna(0).astype('float64') 
ddos['conn_history'] = ddos['conn_history'].fillna("NONE").astype('string')

# Time filter
ddos = ddos[(ddos['timestamp'] >= '2018-12-21 23:07:59') & (ddos['timestamp'] <= '2018-12-21 23:08:20')] # Event 1
# ddos = ddos[(ddos['timestamp'] >= '2019-01-10 14:00:00') & (ddos['timestamp'] <= '2019-01-10 18:00:00')] # Event 2

# Plotting attack 1 
plt.figure(figsize=(10, 6))

# Filter for benign traffic (label=0) and plot
benign = ddos[ddos['label'] == 0]
plt.plot(benign['timestamp'], benign['orig_bytes'], label='Benign Traffic', color='blue')

# Filter for malicious traffic (label=1) and plot
malicious = ddos[ddos['label'] == 1]
plt.plot(malicious['timestamp'], malicious['orig_bytes'], label='Malicious Traffic', color='red')

# Set the labels and title
plt.xlabel('Timestamp')
plt.ylabel('Origin Bytes (Log)')
plt.title('Time Series of Origin Bytes by Traffic Type')

# Add legend to the plot
plt.legend()

# Format the x-axis labels to be more readable
plt.xticks(rotation=45)

# Adjust subplot parameters to fit the figure area
plt.tight_layout()

# Display the plot
plt.show()

# poly_features = PolynomialFeatures(degree=3)

# Looking at unique values

benign = ddos[ddos['label'] == 0]
malicious = ddos[ddos['label'] == 1]

print(malicious["source_ip"].unique())
print(benign["source_ip"].unique())

print(malicious["destination_ip"].unique())
print(benign["destination_ip"].unique())

# print(malicious["source_ip"].unique())
# print(benign["source_ip"].unique())

# print(malicious["conn_history"].unique())
# print(benign["conn_history"].unique())

# Occurance of particular connection history over time 

ddos_test = ddos[(ddos['timestamp'] >= '2018-12-21 23:00:00') & (ddos['timestamp'] <= '2018-12-22 00:00:00')]
ddos_test['timestamp'] = pd.to_datetime(ddos_test['timestamp'])

ddos_dt = ddos[ddos['conn_history'].str.contains('DT')]

# Plotting
plt.figure(figsize=(12, 6))
plt.plot(ddos_dt['timestamp'], ddos_dt['conn_history'].apply(lambda x: x.count('DT')), 'o-')

date_format = mdates.DateFormatter('%Y-%m-%d %H:%M')  
plt.gca().xaxis.set_major_formatter(date_format)
plt.gca().xaxis.set_major_locator(mdates.AutoDateLocator()) 

plt.title('Occurrences of "DT" in Connection History Over Time')
plt.xlabel('Timestamp')
plt.ylabel('Count of DT')
plt.gcf().autofmt_xdate()  
plt.grid(True)
plt.show()

ip1 = '192.168.1.196'
ip2 = '192.168.1.195'
cutoff_value = 5000

ddos_test = ddos[(ddos['timestamp'] >= '2018-12-21 23:00:00') & (ddos['timestamp'] <= '2018-12-22 00:00:00') & (ddos['malware_name'] == 'malicious')]
filtered_ddos = ddos_test[ddos_test['source_ip'].isin([ip1])]

# Ensure timestamp is in datetime format
# filtered_ddos['timestamp'] = pd.to_datetime(filtered_ddos['timestamp'])

# Apply the cutoff value by capping 'orig_bytes' at the cutoff value
filtered_ddos['capped_bytes'] = filtered_ddos['orig_bytes'].clip(upper=cutoff_value)

# Step 2: Group by 'timestamp' and 'source_ip', then sum 'capped_bytes'
grouped = filtered_ddos.groupby(['timestamp', 'source_ip']).sum()['capped_bytes'].unstack()

# Step 3: Plotting
plt.figure(figsize=(12, 6))
for ip in [ip1, ip2]:
    plt.plot(grouped.index, grouped[ip], label=f'Bytes for IP {ip}')

plt.title('Byte Traffic Over Time for Two IPs Bytes)')
plt.xlabel('Timestamp')
plt.ylabel('Bytes (Log))')
plt.legend()
plt.grid(True)
plt.show()

# Finding the time ranges
filtered_df = ddos[(ddos['orig_bytes'] > 500000000) & (ddos['label'] == 1)]

time_min = filtered_df['timestamp'].min()
time_max = filtered_df['timestamp'].max()

# Output the time range
print("Time range where orig_bytes is greater than 5000 and malware_name is 'malicious':")
print(f"Start: {time_min}, End: {time_max}")

# For conn_ddos data
reports_dir = "reports"
summary_stats_dir = f"{reports_dir}/summary_stats"
traffic_vol_dir = f"{reports_dir}/traffic_vol"

ddos_conn = pd.read_csv(f"{traffic_vol_dir}/ddos_report_conn.csv")
ddos_conn = ddos_conn.drop(columns=['malware_name'])

ddos_conn['timestamp'] = pd.to_datetime(ddos_conn['timestamp'])
ddos_conn['label'] = ddos_conn['label'].str.strip().str.lower().map({'benign': 0, 'malicious': 1}).astype('Int64')
ddos_conn['orig_bytes'] = ddos_conn['orig_bytes'].fillna(0).astype('Int64')
ddos_conn['conn_duration'] = ddos_conn['conn_duration'].replace('-', 0).fillna(0).astype('float64') 
ddos_conn['conn_history'] = ddos_conn['conn_history'].fillna("NONE").astype('string')
ddos_conn['conn_state'] = ddos_conn['conn_state'].fillna("NONE").astype('string')

# Time filter
# ddos_conn = ddos_conn[(ddos_conn['timestamp'] >= '2018-12-21 23:07:59') & (ddos_conn['timestamp'] <= '2018-12-21 23:08:20')] # Event 1
# ddos_conn = ddos_conn[(ddos_conn['timestamp'] >= '2019-01-10 14:00:00') & (ddos_conn['timestamp'] <= '2019-01-10 18:00:00')] # Event 2

# Time plot 

plt.figure(figsize=(10, 6))

# Filter for benign traffic (label=0) and plot
benign = ddos_conn[ddos_conn['label'] == 0]
plt.plot(benign['timestamp'], benign['orig_bytes'], label='Benign Traffic', color='blue')

# Filter for malicious traffic (label=1) and plot
malicious = ddos_conn[ddos_conn['label'] == 1]
plt.plot(malicious['timestamp'], malicious['orig_bytes'], label='Malicious Traffic', color='red')

# Set the labels and title
plt.xlabel('Timestamp')
plt.ylabel('Origin Bytes (Log)')
plt.title('Time Series of Origin Bytes by Traffic Type')

# Add legend to the plot
plt.legend()

# Format the x-axis labels to be more readable
plt.xticks(rotation=45)

# Adjust subplot parameters to fit the figure area
plt.tight_layout()

# Display the plot
plt.show()

# Network Graph 

df = ddos[(ddos['label'] == 1)]
df = df[['source_ip', 'destination_ip']].drop_duplicates()
print(df.count())

# Count occurrences of IP pairs
# connection_counts = df.groupby(['source_ip', 'destination_ip']).size().reset_index(name='count')
connection_counts = df.groupby(['source_port', 'destination_port']).size().reset_index(name='count')

# Create a directed graph with edge attribute for 'count'
# G = nx.from_pandas_edgelist(connection_counts, 'source_ip', 'destination_ip', edge_attr='count', create_using=nx.DiGraph())
G = nx.from_pandas_edgelist(connection_counts, 'source_port', 'destination_port', edge_attr='count', create_using=nx.DiGraph())

pos = nx.spring_layout(G, seed=42)


edge_x = []
edge_y = []
annotations = []

for edge in G.edges(data=True):
    x0, y0 = pos[edge[0]]
    x1, y1 = pos[edge[1]]
    edge_x.extend([x0, x1, None])
    edge_y.extend([y0, y1, None])
  
    annotations.append(dict(
        x=(x0 + x1) / 2,
        y=(y0 + y1) / 2,
        xref="x",
        yref="y",
        text=str(edge[2]['count']),  
        showarrow=False,
        font=dict(size=12, color='red'),
        align='center'
    ))

edge_trace = go.Scatter(
    x=edge_x, y=edge_y,
    line=dict(width=1.5, color='grey'),
    hoverinfo='none',
    mode='lines')

node_x = []
node_y = []
node_texts = []  

for node in G.nodes():
    x, y = pos[node]
    node_x.append(x)
    node_y.append(y)
    node_texts.append(node)  

node_trace = go.Scatter(
    x=node_x, y=node_y,
    mode='markers+text',  
    text=node_texts, 
    textposition="top center", 
    hoverinfo='text',
    marker=dict(
        showscale=True,
        colorscale='YlGnBu',
        size=10,
        colorbar=dict(
            thickness=15,
            title='Node Connections',
            xanchor='left',
            titleside='right'
        ),
        color=[len(G.edges(node)) for node in G.nodes()]  
    )
)

fig = go.Figure(data=[edge_trace, node_trace], layout=go.Layout(
    title='Network Graph of DDoS to Benign IP Connections with Counts',
    title_font_size=16,
    showlegend=False,
    hovermode='closest',
    margin=dict(b=20, l=20, r=20, t=40),
    annotations=annotations,
    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
))

fig.show()


# Network Graph 
df = ddos[(ddos['label'] == 1)]
df = df.iloc[:100] # For vis purposes just limit the number 

connection_counts = df.groupby(['source_port', 'destination_port']).size().reset_index(name='count')

G = nx.DiGraph()

destination_port = connection_counts['destination_port'].iloc[0]
G.add_node(destination_port)

for _, row in connection_counts.iterrows():
    G.add_node(row['source_port'])
    G.add_edge(row['source_port'], row['destination_port'], count=row['count'])


pos = {destination_port: (0, 0)}
angle_step = 2 * np.pi / (len(G.nodes()) - 1)  
for i, node in enumerate(G.nodes()):
    if node != destination_port:
        pos[node] = (np.cos(i * angle_step), np.sin(i * angle_step))

# Visualization
edge_trace = go.Scatter(
    x=[pos[edge[0]][0], pos[edge[1]][0], None] + [pos[edge[1]][0], None],
    y=[pos[edge[0]][1], pos[edge[1]][1], None] + [pos[edge[1]][1], None],
    line=dict(width=0.5, color='grey'),
    hoverinfo='none',
    mode='lines')

node_trace = go.Scatter(
    x=[pos[node][0] for node in G.nodes()],
    y=[pos[node][1] for node in G.nodes()],
    mode='markers+text',  
    text=[f"Port {node}" for node in G.nodes()],  
    textposition="top center",
    hoverinfo='text',
    marker=dict(
        showscale=True,
        colorscale='YlGnBu',
        size=10,
        color=[G.in_degree(node) for node in G.nodes()],
        colorbar=dict(
            thickness=15,
            title='Number of Connections',
            xanchor='left',
            titleside='right'
        )
    )
)

fig = go.Figure(data=[edge_trace, node_trace], layout=go.Layout(
    title='Network Graph of Port Connections',
    title_font_size=16,
    showlegend=False,
    hovermode='closest',
    margin=dict(b=20, l=20, r=20, t=40),
    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
))

fig.show()




