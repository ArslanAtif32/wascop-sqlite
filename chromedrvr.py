from selenium import webdriver

driver = webdriver.Chrome()   # Selenium 4.6+ finds/downloads the driver automatically
driver.get("https://www.google.com")