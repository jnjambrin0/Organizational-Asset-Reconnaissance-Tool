"""Manages the SQLite database for storing reconnaissance results."""

import sqlite3
import logging
import os
from datetime import datetime, timedelta
from typing import List, Tuple, Optional, Set
import json # Needed for storing list of IPs as text
from src.core.models import ReconnaissanceResult, ASN, IPRange, Domain, Subdomain, CloudService # Import for type hinting

# Import models ONLY for type hinting if necessary, avoid circular imports
# from .core.models import ReconnaissanceResult, ASN, IPRange, Domain, Subdomain, CloudService 

logger = logging.getLogger(__name__)

# Database file path (relative to project root)
DB_FILE = "recon_results.db"
DATE_FORMAT_DB = "%Y-%m-%d %H:%M:%S.%f" # Store microseconds for uniqueness

def get_db_connection() -> sqlite3.Connection:
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(DB_FILE, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row # Access columns by name
    # Enable foreign key support
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    """Initializes the database and creates tables if they don't exist."""
    logger.info(f"Initializing database at: {os.path.abspath(DB_FILE)}")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # --- Create Tables ---

        # 1. Scans Table (Main entry point for a scan)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_organization TEXT NOT NULL,
            scan_timestamp TIMESTAMP NOT NULL,
            notes TEXT
            -- Add other overall scan metadata if needed
        );
        """)
        logger.debug("Table 'scans' checked/created.")

        # 2. ASNs Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS asns (
            asn_number INTEGER PRIMARY KEY,
            name TEXT,
            description TEXT,
            country TEXT,
            data_source TEXT
        );
        """)
        logger.debug("Table 'asns' checked/created.")
        
        # 3. Scan_ASNs Table (Many-to-Many link between Scans and ASNs)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_asns (
            scan_id INTEGER NOT NULL,
            asn_number INTEGER NOT NULL,
            PRIMARY KEY (scan_id, asn_number),
            FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE,
            FOREIGN KEY (asn_number) REFERENCES asns (asn_number) ON DELETE CASCADE
        );
        """)
        logger.debug("Table 'scan_asns' checked/created.")

        # 4. IP Ranges Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_ranges (
            ip_range_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            cidr TEXT NOT NULL, -- Removed global UNIQUE constraint
            version INTEGER,
            asn_number INTEGER, -- Link to ASN
            country TEXT,
            data_source TEXT,
            UNIQUE (scan_id, cidr), -- Ensure CIDR is unique PER SCAN
            FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE,
            FOREIGN KEY (asn_number) REFERENCES asns (asn_number) ON DELETE SET NULL
        );
        """)
        # Index for faster lookups?
        # cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_ranges_cidr ON ip_ranges (cidr);") # Indexing only cidr might not be as useful now
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_ranges_scan_cidr ON ip_ranges (scan_id, cidr);") # Index composite key
        logger.debug("Table 'ip_ranges' checked/created.")

        # 5. Domains Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS domains (
            domain_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            registrar TEXT,
            creation_date TIMESTAMP,
            data_source TEXT,
            UNIQUE (scan_id, name), -- Domain name should be unique per scan
            FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
        );
        """)
        logger.debug("Table 'domains' checked/created.")

        # 6. Subdomains Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS subdomains (
            subdomain_id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER NOT NULL, -- Link to parent Domain
            fqdn TEXT NOT NULL UNIQUE, -- FQDN should ideally be globally unique?
            status TEXT,
            resolved_ips TEXT, -- Store as JSON list string
            data_source TEXT,
            last_checked TIMESTAMP,
            FOREIGN KEY (domain_id) REFERENCES domains (domain_id) ON DELETE CASCADE
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_subdomains_fqdn ON subdomains (fqdn);")
        logger.debug("Table 'subdomains' checked/created.")

        # 7. Cloud Services Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS cloud_services (
            cloud_service_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            provider TEXT NOT NULL,
            identifier TEXT NOT NULL, -- IP or domain
            resource_type TEXT,
            region TEXT,
            status TEXT,
            data_source TEXT,
            UNIQUE (scan_id, provider, identifier), -- Unique service per scan
            FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
        );
        """)
        logger.debug("Table 'cloud_services' checked/created.")
        
        # 8. Scan Warnings Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_warnings (
            warning_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
        );
        """)
        logger.debug("Table 'scan_warnings' checked/created.")


        conn.commit()
        logger.info("Database initialization complete.")

    except sqlite3.Error as e:
        logger.exception(f"Database error during initialization: {e}")
        # Consider how to handle initialization errors - maybe raise exception?
    finally:
        if conn:
            conn.close()

# --- Add placeholder functions for saving and loading ---
# We will implement these next.

def save_scan_result(result: ReconnaissanceResult):
    """Saves a full ReconnaissanceResult object to the database transactionally."""
    scan_timestamp = datetime.now()
    logger.info(f"Attempting to save scan results for '{result.target_organization}' at {scan_timestamp.strftime(DATE_FORMAT_DB)}")
    conn = None # Initialize conn to None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Start transaction
        conn.execute("BEGIN TRANSACTION")
        
        # 1. Insert Scan Record
        cursor.execute("""
            INSERT INTO scans (target_organization, scan_timestamp) 
            VALUES (?, ?)
        """, (result.target_organization, scan_timestamp))
        scan_id = cursor.lastrowid
        logger.debug(f"Inserted scan record with ID: {scan_id}")
        
        # --- Insert related data --- 
        
        # 2. ASNs (Insert or Ignore if exists, then link to scan)
        if result.asns:
            asn_data = [
                (asn.number, asn.name, asn.description, asn.country, asn.data_source)
                for asn in result.asns
            ]
            cursor.executemany("""
                INSERT OR IGNORE INTO asns (asn_number, name, description, country, data_source)
                VALUES (?, ?, ?, ?, ?)
            """, asn_data)
            logger.debug(f"Inserted/ignored {len(asn_data)} ASNs into 'asns' table.")
            
            # Link ASNs to this scan
            scan_asn_links = [(scan_id, asn.number) for asn in result.asns]
            cursor.executemany("""
                INSERT INTO scan_asns (scan_id, asn_number)
                VALUES (?, ?)
            """, scan_asn_links)
            logger.debug(f"Linked {len(scan_asn_links)} ASNs to scan {scan_id}.")

        # 3. IP Ranges (Insert OR IGNORE and link to scan and potentially ASN)
        if result.ip_ranges:
            ip_range_data = [
                (
                    scan_id, 
                    ipr.cidr, 
                    ipr.version, 
                    ipr.asn.number if ipr.asn else None, 
                    ipr.country, 
                    ipr.data_source
                )
                for ipr in result.ip_ranges
            ]
            cursor.executemany("""
                INSERT OR IGNORE INTO ip_ranges (scan_id, cidr, version, asn_number, country, data_source)
                VALUES (?, ?, ?, ?, ?, ?)
            """, ip_range_data)
            # Log affected rows to see if any were ignored (optional)
            if cursor.rowcount != len(ip_range_data):
                 logger.warning(f"Attempted to insert {len(ip_range_data)} IP ranges, but {cursor.rowcount} rows were affected. Some might have been ignored due to UNIQUE(scan_id, cidr) constraint.")
            else:
                 logger.debug(f"Inserted {cursor.rowcount} IP ranges for scan {scan_id}.")

        # 4. Domains and their Subdomains
        if result.domains:
            for domain in result.domains:
                # Insert Domain
                cursor.execute("""
                    INSERT INTO domains (scan_id, name, registrar, creation_date, data_source)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    scan_id, 
                    domain.name, 
                    domain.registrar, 
                    domain.creation_date, 
                    domain.data_source
                ))
                domain_id = cursor.lastrowid
                logger.debug(f"Inserted domain '{domain.name}' with ID {domain_id} for scan {scan_id}.")
                
                # Insert Subdomains for this Domain
                if domain.subdomains:
                    logger.debug(f"Preparing to insert {len(domain.subdomains)} subdomains for domain ID {domain_id}...")
                    subdomain_data = [
                        (
                            domain_id, 
                            sub.fqdn, 
                            sub.status, 
                            json.dumps(sorted(list(sub.resolved_ips))) if sub.resolved_ips else None, 
                            sub.data_source, 
                            sub.last_checked
                        )
                        for sub in domain.subdomains
                    ]
                    # Log a sample of subdomain data being prepared
                    if subdomain_data:
                         logger.debug(f"Sample subdomain data for domain {domain_id}: {subdomain_data[0]}")
                         
                    cursor.executemany("""
                        INSERT OR IGNORE INTO subdomains (domain_id, fqdn, status, resolved_ips, data_source, last_checked)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, subdomain_data) # Use OR IGNORE assuming FQDN is unique globally
                    
                    # Check affected rows
                    affected_rows = cursor.rowcount
                    logger.debug(f"Subdomain INSERT OR IGNORE for domain ID {domain_id} affected {affected_rows} rows (attempted: {len(subdomain_data)}). Some might have been ignored.")
                else:
                     logger.debug(f"No subdomains found for domain '{domain.name}' (ID: {domain_id}) in the result object.")

        # 5. Cloud Services
        if result.cloud_services:
            cloud_data = [
                (
                    scan_id, 
                    svc.provider, 
                    svc.identifier, 
                    svc.resource_type, 
                    svc.region, 
                    svc.status, 
                    svc.data_source
                )
                for svc in result.cloud_services
            ]
            cursor.executemany("""
                INSERT INTO cloud_services (scan_id, provider, identifier, resource_type, region, status, data_source)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, cloud_data)
            logger.debug(f"Inserted {len(cloud_data)} cloud services for scan {scan_id}.")
            
        # 6. Warnings
        if result.warnings:
            warning_data = [(scan_id, msg) for msg in result.warnings]
            cursor.executemany("""
                INSERT INTO scan_warnings (scan_id, message)
                VALUES (?, ?)
            """, warning_data)
            logger.debug(f"Inserted {len(warning_data)} warnings for scan {scan_id}.")

        # Commit transaction
        conn.commit()
        logger.info(f"Successfully saved scan result {scan_id} for '{result.target_organization}'.")
        
    except sqlite3.Error as e:
        logger.exception(f"Database error during save_scan_result for '{result.target_organization}': {e}")
        if conn:
            conn.rollback() # Roll back changes on error
        # Optionally re-raise or handle error
    except Exception as e:
        logger.exception(f"Unexpected error during save_scan_result: {e}")
        if conn:
             conn.rollback()
    finally:
        if conn:
            conn.close()

def get_scan_history(limit: int = 10) -> List[sqlite3.Row]:
    """Retrieves recent scan history metadata from the database."""
    scans = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT scan_id, target_organization, scan_timestamp 
            FROM scans 
            ORDER BY scan_timestamp DESC 
            LIMIT ?
        """, (limit,))
        scans = cursor.fetchall()
        logger.debug(f"Retrieved {len(scans)} records from scan history.")
    except sqlite3.Error as e:
        logger.exception(f"Database error retrieving scan history: {e}")
    finally:
        if conn:
            conn.close()
    return scans

def get_result_by_scan_id(scan_id: int) -> Optional[ReconnaissanceResult]: 
    """Reconstructs a ReconnaissanceResult object from the database using a scan_id."""
    logger.info(f"Attempting to load scan result for scan_id: {scan_id}")
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # 1. Get main scan info
        cursor.execute("SELECT target_organization FROM scans WHERE scan_id = ?", (scan_id,))
        scan_row = cursor.fetchone()
        if not scan_row:
            logger.error(f"Scan with ID {scan_id} not found.")
            return None
        
        result = ReconnaissanceResult(target_organization=scan_row['target_organization'])
        logger.debug(f"Reconstructing result for target: {result.target_organization}")

        # 2. Get ASNs
        cursor.execute("""
            SELECT a.* 
            FROM asns a
            JOIN scan_asns sa ON a.asn_number = sa.asn_number
            WHERE sa.scan_id = ?
        """, (scan_id,))
        asn_rows = cursor.fetchall()
        result.asns = {
            ASN(
                number=row['asn_number'], # Explicit mapping
                name=row['name'],
                description=row['description'],
                country=row['country'],
                data_source=row['data_source']
            ) 
            for row in asn_rows 
        }
        logger.debug(f"Loaded {len(result.asns)} ASNs.")

        # Temp mapping for ASN objects for IP ranges
        asn_map = {asn.number: asn for asn in result.asns}

        # 3. Get IP Ranges
        cursor.execute("""
            SELECT cidr, version, asn_number, country, data_source
            FROM ip_ranges 
            WHERE scan_id = ?
        """, (scan_id,))
        ip_range_rows = cursor.fetchall()
        result.ip_ranges = {
            IPRange(
                cidr=row['cidr'], 
                version=row['version'], 
                asn=asn_map.get(row['asn_number']), # Link ASN object
                country=row['country'],
                data_source=row['data_source']
            ) for row in ip_range_rows
        }
        logger.debug(f"Loaded {len(result.ip_ranges)} IP Ranges.")

        # 4. Get Domains and their Subdomains (Optimized)
        cursor.execute("""
            SELECT domain_id, name, registrar, creation_date, data_source
            FROM domains
            WHERE scan_id = ?
        """, (scan_id,))
        domain_rows = cursor.fetchall()
        
        # Create Domain objects and map by ID
        domains_map = {}
        for domain_row in domain_rows:
            domain_obj = Domain(
                name=domain_row['name'],
                registrar=domain_row['registrar'],
                creation_date=domain_row['creation_date'],
                data_source=domain_row['data_source'],
                subdomains=set() # Initialize with empty set
            )
            domains_map[domain_row['domain_id']] = domain_obj
            
        if domains_map: # Only query subdomains if there are domains
            domain_ids = tuple(domains_map.keys()) # Get IDs for the IN clause
            
            # Fetch all relevant subdomains in one query
            cursor.execute(f"""
                SELECT domain_id, fqdn, status, resolved_ips, data_source, last_checked
                FROM subdomains
                WHERE domain_id IN ({','.join(['?']*len(domain_ids))})
            """, domain_ids)
            subdomain_rows = cursor.fetchall()
            logger.debug(f"Fetched {len(subdomain_rows)} total subdomain rows for {len(domain_ids)} domains in scan {scan_id}.")
            
            # Associate subdomains with their respective domains
            associated_count = 0
            for sub_row in subdomain_rows:
                domain_id = sub_row['domain_id']
                fqdn = sub_row['fqdn'] # For logging
                if domain_id in domains_map:
                    try:
                        resolved_ips_set = set(json.loads(sub_row['resolved_ips'])) if sub_row['resolved_ips'] else set()
                        subdomain_obj = Subdomain(
                             fqdn=fqdn,
                             status=sub_row['status'],
                             resolved_ips=resolved_ips_set,
                             data_source=sub_row['data_source'],
                             last_checked=sub_row['last_checked']
                        )
                        domains_map[domain_id].subdomains.add(subdomain_obj)
                        associated_count += 1
                        # logger.debug(f"Associated subdomain '{fqdn}' with domain ID {domain_id}") # Potentially too verbose
                    except json.JSONDecodeError as json_err:
                         logger.error(f"Failed to decode resolved_ips JSON for subdomain {fqdn} (domain_id {domain_id}): {json_err}")
                         result.add_warning(f"Subdomain Load Error: Failed to parse IPs for {fqdn}")
                    except Exception as assoc_err:
                         logger.error(f"Error associating subdomain {fqdn} with domain ID {domain_id}: {assoc_err}")
                         result.add_warning(f"Subdomain Load Error: Failed to process {fqdn}")

                else:
                    # This shouldn't happen due to the WHERE clause, but good to log if it does
                    logger.warning(f"Found subdomain '{fqdn}' for unknown domain_id {domain_id} during load for scan {scan_id}.")
            logger.debug(f"Successfully associated {associated_count} subdomains with their parent domains.")

        result.domains = set(domains_map.values()) # Get the Domain objects from the map
        logger.debug(f"Loaded {len(result.domains)} domains and their subdomains.")

        # 5. Get Cloud Services
        cursor.execute("""
            SELECT provider, identifier, resource_type, region, status, data_source
            FROM cloud_services
            WHERE scan_id = ?
        """, (scan_id,))
        cloud_rows = cursor.fetchall()
        result.cloud_services = {CloudService(**dict(row)) for row in cloud_rows}
        logger.debug(f"Loaded {len(result.cloud_services)} cloud services.")

        # 6. Get Warnings
        cursor.execute("SELECT message FROM scan_warnings WHERE scan_id = ?", (scan_id,))
        warning_rows = cursor.fetchall()
        result.warnings = [row['message'] for row in warning_rows]
        logger.debug(f"Loaded {len(result.warnings)} warnings.")

        logger.info(f"Successfully reconstructed scan result for scan_id: {scan_id}")
        return result

    except sqlite3.Error as e:
        logger.exception(f"Database error loading scan result for scan_id {scan_id}: {e}")
        return None
    except Exception as e:
         logger.exception(f"Unexpected error loading scan result for scan_id {scan_id}: {e}")
         return None
    finally:
        if conn:
            conn.close()

def check_existing_scan(target_organization: str, max_age_hours: int = 24) -> Optional[int]:
    """Checks if a recent scan for the target exists and returns its scan_id."""
    scan_id = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Calculate the cutoff timestamp
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        
        cursor.execute("""
            SELECT scan_id 
            FROM scans 
            WHERE target_organization = ? 
            AND scan_timestamp >= ?
            ORDER BY scan_timestamp DESC 
            LIMIT 1
        """, (target_organization, cutoff_time))
        
        result = cursor.fetchone()
        if result:
            scan_id = result['scan_id']
            logger.info(f"Found recent scan (ID: {scan_id}) for target '{target_organization}'.")
        else:
             logger.debug(f"No recent scan found for target '{target_organization}' within {max_age_hours} hours.")
             
    except sqlite3.Error as e:
        logger.exception(f"Database error checking for existing scan for '{target_organization}': {e}")
    finally:
        if conn:
            conn.close()
    return scan_id

if __name__ == '__main__':
    # Example of initializing the DB when running the script directly
    print("Initializing database...")
    # Setup basic logging for testing
    log_format = '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
    logging.basicConfig(level=logging.DEBUG, format=log_format)
    init_db()
    print("Database initialization finished. Check 'recon_results.db'.") 