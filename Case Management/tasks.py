from datetime import datetime
from db_connect import DatabaseManager  # Adjust import as needed

def check_and_insert_arrests():
    db_manager = DatabaseManager()
    # This query lists cases with target statuses that haven't been processed.
    # Here, we set a default value for suspect_name directly in the SQL query.
    query = """
        SELECT id, 'Unknown Suspect' AS suspect_name, status 
        FROM cases 
        WHERE status IN ('In Custody', 'Under Questioning', 'Under Investigation')
          AND id NOT IN (SELECT case_id FROM arrests)
    """
    cases_to_process = db_manager.fetch_all(query)
    for case in cases_to_process:
        insert_query = """
            INSERT INTO arrests (case_id, suspect_name, outcome, arrest_date)
            VALUES (%s, %s, %s, %s)
        """
        db_manager.execute_query(
            insert_query,
            (case['id'], case['suspect_name'], 'Pending', datetime.now())
        )
    db_manager.close_connection()

# For testing or manual run:
if __name__ == "__main__":
    check_and_insert_arrests()
