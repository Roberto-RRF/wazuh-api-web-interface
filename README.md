# Wazuh API Dashboard Project

## Project Overview
This project presents a dashboard built with Flask, utilizing the Wazuh API to monitor vulnerabilities and agents within a network security environment. The dashboard offers features to visualize and manage agent statuses and vulnerabilities, aiding in proactive security management.

## Key Features

- **Agent Monitoring**: Displays a list of the top N agents with their status, operating system, and total vulnerabilities.
- **Vulnerability Tracking**: Summarizes vulnerabilities by severity (Critical, High, Medium, Low) across all agents.
- **Search Functionality**: Allows users to search for vulnerabilities related to specific agents, CVE IDs, or keywords.
- **Data Insights**: Provides detailed views into the vulnerabilities associated with each agent, grouped by operating systems and severity levels.

## Technology Stack
- **Backend**: Python with Flask
- **Frontend**: HTML templates
- **API**: Wazuh API for fetching real-time data about agents and vulnerabilities

## Setup and Running the Project

1. Ensure Python and Flask are installed on your system.
2. Download or clone this project repository to your local machine.
3. Navigate to the project directory in your terminal.
4. Run the application using the command:

python app.py

5. Open a web browser and access the dashboard at:

http://localhost:8000

## Development Team
- Luis Guillen
- Roberto Requejo
- Joel Vazquez
- Diego Heredia
