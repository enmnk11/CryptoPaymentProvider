import requests
import hmac
import hashlib
from decouple import config

class Oxapay:
    """
    Oxapay es una plataforma de pagos que permite a los usuarios pagar por servicios y productos.
    Documentacion: https://docs.oxapay.com/
    """

    def __init__(self):
        self.MERCHANT_API_KEY = config("OXAPAY_MERCHANT_API_KEY")
        self.API_URL = config("OXAPAY_API_URL")
        self.headers = {
            "Content-Type": "application/json",
            "merchant_api_key": f"{self.MERCHANT_API_KEY}"
        }

    def create_invoice(self, payload):
        """
        Crea una factura para un pago.

        Args:
            payload (dict): Los datos de la factura.

        Returns:
            dict: Los datos de la factura.
        """
        try:
            url = f"{self.API_URL}/payment/invoice"
            response = requests.post(url, headers=self.headers, json=payload)
            return response.json()
        except Exception as e:
            print(e)
            return ValueError("Error al crear la factura")
        
    def generate_static_address(self, payload):
        """
        Genera una dirección estática para un pago.

        Args:
            payload (dict): Los datos de la factura.
            Required fields:
                - network: str

        Returns:
            dict: Los datos de la factura.
        """
        try:
            url = f"{self.API_URL}/payment/static-address"
            response = requests.post(url, headers=self.headers, json=payload)
            return response.json()
        except Exception as e:
            print(e)
            return ValueError("Error al generar la dirección estática")
        
    def revoke_static_address(self, address):
        """
        Revoca una dirección estática para un pago.

        Args:
            address (str): La dirección estática a revocar.

        Returns:
            dict: Los datos de la factura.
        """
        try:
            url = f"{self.API_URL}/payment/static-address/revoke"
            response = requests.post(url, headers=self.headers, json={"address": address})
            return response.json()
        except Exception as e:
            print(e)
            return ValueError("Error al revocar la dirección estática")

    def get_payment_info(self, track_id):
        """
        Obtiene información de un pago por su ID de seguimiento.

        Args:
            track_id (str): El ID de seguimiento de la factura.
        
        Returns:
            dict: Los datos del pago.
        """
        try:
            url = f"{self.API_URL}/payment/{track_id}"
            response = requests.get(url, headers=self.headers)
            return response.json()  
        except Exception as e:
            print(e)
            return ValueError("Error al obtener la información del pago")

    def verify_callback_signature(self, raw_data, hmac_header):
        """
        Verifica la firma HMAC del callback de pago.

        Args:
            raw_data (bytes): Datos raw del callback
            hmac_header (str): Firma HMAC recibida en el header

        Returns:
            bool: True si la firma es válida, False en caso contrario

        Usage:
            raw_data = request.data
            hmac_header = request.headers.get("HMAC")
            oxapay = Oxapay()

            if oxapay.verify_callback_signature(raw_data, hmac_header):
                print("Firma válida")
            else:
                print("Firma inválida")
        """
        try:
            # Calcular el HMAC usando SHA512
            calculated_hmac = hmac.new(
                self.MERCHANT_API_KEY.encode(),
                raw_data,
                hashlib.sha512
            ).hexdigest()

            # Comparar las firmas
            return hmac.compare_digest(calculated_hmac, hmac_header)
        except Exception as e:
            print(f"Error al verificar la firma HMAC: {e}")
            return False