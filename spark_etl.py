from pyspark.sql import SparkSession
import pyspark.sql.functions as F
from pyspark.sql import DataFrame
from pyspark.sql.types import DoubleType, IntegerType, TimestampType

import os
import math

import matplotlib.pyplot as plt
import pandas as pd
from functools import reduce
import plotly.express as px

dataset_dir = "/home/jon/Documents/Grad_School/AIT580/Project/Dataset/opt/Malware-Project/BigDataset/IoTScenarios"

reports_dir = "reports"
summary_stats_dir = f"{reports_dir}/summary_stats"
traffic_vol_dir = f"{reports_dir}/traffic_vol"
conn_history_dir = f"{reports_dir}/conn_history"
port_proto_dir = f"{reports_dir}/port_proto"

def clean_data(data_file, spark):
    dfs = []
    for root, dirs, files in os.walk(data_file):
        for file in files:
            if file.endswith("conn.log.labeled"):
                file_path = os.path.join(root, file)
                
                df = spark.read.option("header", "true") \
                            .option("sep", "\t") \
                            .option("comment", "#") \
                            .csv(file_path)
                dfs.append(df)
    df = reduce(DataFrame.unionAll,dfs)

    # The last 3 cols did not have \t so this is a fix for that
    last_col = df.columns[-1]
    split_col = F.split(df[last_col], '\s+')
    df = df.withColumn("tunnel_parents", split_col.getItem(0))
    df = df.withColumn("label", split_col.getItem(1))
    df = df.withColumn("detailed-label", split_col.getItem(2))
    df = df.drop(last_col)

    headers = ["timestamp", "connection_uid", "source_ip", "source_port", "destination_ip", "destination_port", "conn_proto", "app_proto_service", "conn_duration",
                        "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "conn_history", 
                        "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "label", "malware_name"]

    iot23 = df.toDF(*headers)

    # Data Cleaning and Transformations
    # --------------------------------------------

    # Capitalize benign 
    iot23 = iot23.withColumn("label", F.when(F.col("label") == "benign", "Benign").otherwise(F.col("label")))

    # Replace null values with Benign as "-" values are all Benign
    iot23 = iot23.withColumn("malware_name", F.when(F.col("malware_name") == "-", "Benign").otherwise(F.col("malware_name")))

    # Don't need these for analysis 
    iot23 = iot23.drop("local_orig", "local_resp", "tunnel_parents")

    # Type Casting 
    iot23 = iot23.withColumn("orig_bytes", F.col("orig_bytes").cast(DoubleType()))
    iot23 = iot23.withColumn("resp_bytes", F.col("resp_bytes").cast(DoubleType()))
    iot23 = iot23.withColumn("orig_ip_bytes", F.col("orig_ip_bytes").cast(DoubleType()))
    iot23 = iot23.withColumn("resp_ip_bytes", F.col("resp_ip_bytes").cast(DoubleType()))

    iot23 = iot23.withColumn("orig_pkts", F.col("orig_pkts").cast(IntegerType()))
    iot23 = iot23.withColumn("resp_pkts", F.col("resp_pkts").cast(IntegerType()))

    # Convert to timestamp 
    iot23 = iot23.withColumn("timestamp", F.from_unixtime("timestamp").cast(TimestampType()))

    return(iot23)

#######################
#### General Info ######
#######################

def malware_counts_by_name_report(data):
    malware_counts = data.groupBy("malware_name").count()
    malware_counts = malware_counts.toPandas()

    malware_counts.to_csv(f"{summary_stats_dir}/malware_counts_by_name.csv", index=False)

#######################
#### Traffic Vol ######
#######################
traffic_volumn_cols = ["orig_bytes", "resp_bytes", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"]
ddos_cols = ["timestamp", "label", "malware_name", "orig_bytes", "source_ip", 
                                  "source_port", "destination_ip", "destination_port", "conn_duration", "conn_history"]
traffic_volumn_timeseries_cols = ["timestamp", "label", "malware_name", "orig_bytes", "source_ip", 
                                  "source_port", "destination_ip", "destination_port", "conn_proto", "app_proto_service", "conn_duration", "conn_history"]
traffic_volumn_select_cols = traffic_volumn_cols + ["label", "malware_name"]

origin_bytes_threshold = 23617321450 # Obtained by running add_traffic_volumn_category. Takes the high threshold or q75. 

def get_traffic_volumn_df(iot23):
    traffic_volumn = iot23.select(traffic_volumn_select_cols).na.fill(0)
    return(traffic_volumn)

def get_traffic_volumn_benign_df(traffic_volumn):
    traffic_volumn_benign = traffic_volumn.filter((F.col("label") != "malicious"))
    return(traffic_volumn_benign)

def add_traffic_volumn_category(iot23):
    for column in traffic_volumn_cols:
        # quantiles based on benign traffic volumns
        traffic_volumn = get_traffic_volumn_df(iot23)
        traffic_volumn_benign = get_traffic_volumn_benign_df(traffic_volumn)

        q25, q75, q95 = traffic_volumn_benign.approxQuantile(column, [0.25, 0.75, 0.95], 0.01)
            
        traffic_volumn = traffic_volumn.withColumn(column + "_traffic_volume_category",
                            F.when(F.col(column) <= q25, "low")
                            .when((F.col(column) > q25) & (F.col(column) <= q75), "normal")
                            .when((F.col(column) > q75) & (F.col(column) <= q95), "high")
                            .otherwise("very_high"))
        
    return(traffic_volumn)

def traffic_volumn_by_name_report(iot23):
    traffic_volumn = add_traffic_volumn_category(iot23)

    traffic_volume_columns = [c for c in traffic_volumn.columns if "_traffic_volume_category" in c]

    agg_exprs = []
    for column in traffic_volume_columns:
        for category in ["low", "normal", "high", "very_high"]:
            # Create aggregate expression for each category in each column
            agg_expr = F.sum(F.when(F.col(column) == category, 1).otherwise(0)).alias(f"{column}_{category}_count")
            agg_exprs.append(agg_expr)

    # Perform the groupBy and aggregate operations
    traffic_volumn_report = traffic_volumn.groupBy("malware_name").agg(*agg_exprs)

    # Convert to Pandas DataFrame and save to CSV
    traffic_volumn_report_df = traffic_volumn_report.toPandas()
    traffic_volumn_report_df.to_csv(f"{traffic_vol_dir}/traffic_volumn_report.csv", index=False)

def generate_origin_bytes_data_report(iot23):
    traffic_volumn_timeseries_df = iot23.select(traffic_volumn_timeseries_cols)
    traffic_volumn_timeseries_df = traffic_volumn_timeseries_df.filter((F.col("orig_bytes") > origin_bytes_threshold))

    traffic_volumn_timeseries_df = traffic_volumn_timeseries_df.toPandas()
    traffic_volumn_timeseries_df.to_csv(f"{traffic_vol_dir}/origin_bytes_high_data_report.csv", index=False)

def ddos_report(iot23):
    ddos_cols = ["timestamp", "label", "malware_name", "orig_bytes", "conn_duration", "conn_history", "conn_state"]
    ddos_df = iot23.select(ddos_cols)
    ddos_df = ddos_df.filter(ddos_df["malware_name"].isin("Benign", "DDoS"))

    ddos_df = ddos_df.toPandas()
    ddos_df.to_csv(f"{traffic_vol_dir}/ddos_report_conn.csv", index=False)

def main():
    spark = SparkSession.builder \
        .appName("IoT23_ETL") \
        .config("spark.master", "local[*]") \
        .config("spark.driver.memory", "32g") \
        .config("spark.executor.memory", "32g") \
        .getOrCreate()
    
    ###### Data Cleaning #####
    ############################################

    iot23 = clean_data(dataset_dir, spark)
    
    ##### General Info #######
    ############################################

    # malware_counts_by_name_report(iot23)

    ##### Traffic Volumn #######
    ############################################

    #traffic_volumn_by_name_report(iot23)
    # add_traffic_volumn_category(iot23)
    # generate_origin_bytes_data_report(iot23)
    # ddos_report(iot23)

    spark.stop()

if __name__ == "__main__":
    main()