#Make working directory global
knitr::opts_knit$set(root.dir = "/home/jon/Documents/Grad_School/AIT580/Project/")
library(reticulate)
use_virtualenv("~/R_virtualenv", required = TRUE)
library(plyr); 
library(dplyr); 
library(tidyr);
library(ggplot2);
library(maps);
library(patchwork);
library(tidyverse);
library(lubridate);
library(magrittr);
library(gt);
library(lubridate)
library(maps)
library(knitr)
library(kableExtra)
library(gridExtra)
library(httr)
library(aws.s3)
library(sparklyr)
library(scales)

# Vars
reports_dir <- "reports"
summary_stats_dir <- paste0(reports_dir, "/summary_stats")
traffic_vol_dir <- paste0(reports_dir, "/traffic_vol")

# Helper Functions 

# Function to extract out low, normal, high, very high strings for traffic volume 
get_traffic_val <- function(column_name) {
  if (grepl("very_high", column_name)) {
    return("very_high")
  } else if (grepl("high", column_name)) {
    return("high")
  } else if (grepl("low", column_name)) {
    return("low")
  } else if (grepl("normal", column_name)) {
    return("normal")
  } else {
    return(NA)
  }
}


# Malware Type Counts
malware_counts_report <- paste0(summary_stats_dir, "/malware_counts_by_name.csv")
malware_counts_report <- read.csv(malware_counts_report, stringsAsFactors = FALSE)

ggplot(malware_counts_report, aes(x = reorder(malware_name, count), y = count)) +
  geom_bar(stat = "identity", aes(fill = malware_name == "Benign")) +
  scale_fill_manual(values = c("TRUE" = "blue", "FALSE" = "red")) + 
  scale_y_log10() +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1)) + 
  labs(title = "Malware Type Counts", x = "Malware Type", y = "Count (Log Scale)")

kable(malware_counts_report, caption = "Malware Type Counts", 
      align = 'l', 
      format = "markdown")  %>% 
  kable_styling(font_size = 5.9)

# Plot all volume flows
traffic_volume_summary_report <- paste0(traffic_vol_dir, "/traffic_volume_summary.csv")
traffic_volume_summary_report <- read.csv(traffic_volume_summary_report, stringsAsFactors = FALSE)

traffic_volume_by_name_report <- paste0(traffic_vol_dir, "/traffic_volume_by_name.csv")
traffic_volume_by_name_report <- read.csv(traffic_volume_by_name_report, stringsAsFactors = FALSE)

kable(traffic_volume_summary_report, caption = "Traffic Volume Summary", 
      align = 'l', 
      format = "markdown")  %>% 
  kable_styling(font_size = 5.9)

ggplot(malware_counts_report, aes(x = reorder(malware_name, count), y = count)) +
  geom_bar(stat = "identity", aes(fill = malware_name == "Benign")) +
  scale_fill_manual(values = c("TRUE" = "blue", "FALSE" = "red")) + 
  scale_y_log10() +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1)) + 
  labs(title = "Malware Type Counts", x = "Malware Type", y = "Count (Log Scale)")

num_cols <- ncol(traffic_volume_by_name_report)
column_names <- colnames(traffic_volume_by_name_report)

column_names <- column_names[column_names != "malware_name"]
column_names <- sub("_category.*", "", column_names)
column_names <- unique(column_names)
num_categories <- 4
num_traffic_types <- length(column_names)

initial_cat_i <- 2
initial_cat_j <- 5

# Iterate over all traffic types. Adjust the range as necessary.
for (traffic_type_i in 1:num_traffic_types) {
  plots <- list()
  cat_i <- initial_cat_i
  cat_j <- initial_cat_j

  for (cat_idx in cat_i:cat_j) {
    count <- traffic_volume_by_name_report[[cat_idx]]
    traffic_type = get_traffic_val(names(traffic_volume_by_name_report[cat_idx]))

    plot <- ggplot(traffic_volume_by_name_report, aes(x = reorder(malware_name, -count), y = count)) +
        geom_bar(stat = "identity", aes(fill = malware_name == "Benign")) +
        scale_fill_manual(values = c("TRUE" = "blue", "FALSE" = "red")) +
        scale_y_log10() +
        theme_minimal() +
        theme(axis.text.x = element_text(angle = 45, hjust = 1),
              legend.position = "none") + # Remove legend
        labs(title = paste(column_names[traffic_type_i], traffic_type), x = "Malware Type", y = "Count")

    plots <- append(plots, list(plot))

    # Print two plots at a time, side by side
    if (length(plots) == 1) {
      do.call(grid.arrange, c(plots, ncol = 1))
      plots <- list()
    }
  }

  # Check if there's an odd number of plots and display the last one if needed
  if (length(plots) == 1) {
    print(plots[[1]])
  }

  initial_cat_i <- initial_cat_i + num_categories
  initial_cat_j <- initial_cat_j + num_categories
}

