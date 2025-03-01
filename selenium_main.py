
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException, NoSuchElementException
import json
import time

def get_policy_info(search_query: str) -> str:
    """Fetch insurance policy information from Bedrock Insurance portal and return formatted JSON."""
    driver = None
    try:
        # Initialize webdriver
        options = webdriver.ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        driver = webdriver.Chrome(options=options)

        # Login process
        driver.get("https://gisa.bedrockinsurance.com.gh/")
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, "user_email"))
        ).send_keys("BABANKWA")
        driver.find_element(By.ID, "user_password").send_keys("B1r2i3g4h5t6@123.com")
        driver.find_element(By.NAME, "commit").click()

        # Navigate and search
        driver.get("https://gisa.bedrockinsurance.com.gh/motor_policies")
        search_input = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.NAME, "name_or_number"))
        )
        search_input.send_keys(search_query)
        driver.find_element(By.NAME, "button").click()

        # Click first result
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "td a"))
        ).click()

        # Improved element value retrieval with fallback
        def get_element_value(element_id, get_text=False):
            try:
                element = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.ID, element_id))
                )
                value = element.text.strip() if get_text else element.get_attribute("value").strip()
                return value if value else "Not Available"
            except:
                return "Not Available"

        # Collect all data points
        customer_name = get_element_value("motor_policy_customer_name")
        policy_number = get_element_value("motor_policy_number")
        intermediary = get_element_value("motor_policy_intermediary_name")
        
        vehicle_reg = get_element_value("motor_policy_vehicle_registration")
        vehicle_make = get_element_value("select2-motor_policy_vehicle_make_id-container", True)
        vehicle_model = get_element_value("select2-motor_policy_vehicle_model_id-container", True)
        vehicle_color = get_element_value("motor_policy_color")

        cover_type = get_element_value("select2-motor_policy_cover_type_id-container", True)
        computation_type = get_element_value("select2-motor_policy_computation_type_id-container", True)
        duration_days = get_element_value("motor_policy_number_of_days")
        inception_date = get_element_value("motor_policy_inception_date")
        expiry_date = get_element_value("motor_policy_expiry_date")
        premium = get_element_value("motor_policy_total_premium")

        # Structure output for clarity
                # Build Markdown output
        output = f"""
**Insurance Policy Details**

**Customer Information**
- Policy Holder: {customer_name}
- Policy Number: {policy_number}
- Intermediary: {intermediary}

**Vehicle Details** 
- Registration: {vehicle_reg}
- Make: {vehicle_make}
- Model: {vehicle_model}
- Color: {vehicle_color}

**Coverage Summary**
- Insurance Type: {cover_type}
- Duration: {computation_type} ({duration_days} days)
- Coverage Period: {inception_date} to {expiry_date}
- Total Premium: GHS {premium}

*All information current as of {time.strftime('%Y-%m-%d')}*
        """.strip()

        return output

    except TimeoutException:
        return "⚠️ Error: System timeout occurred. Please try again later."

    except WebDriverException as e:
        return f"⚠️ Connection Error: {str(e)}"

    except Exception as e:
        return f"⚠️ Unexpected Error: {str(e)}"
    
    finally:
        if driver:
            try:
                driver.quit()
            except:
                pass