import base64
import logging
import ujson as json
from collections import UserDict
from typing import Dict, Union, Callable, Set

from bson import DBRef
from bson.objectid import ObjectId
from cryptography.fernet import Fernet
from mongoengine import connect, Document, BinaryField, ListField, DictField
from mongoengine.base import TopLevelDocumentMetaclass, BaseField
from mongoengine.queryset.base import BaseQuerySet

log = logging.getLogger(__name__)

key = None
fernet = None

db_name = "virts"

prefix = b'$$$$:'  # Used to prevent double encryption


def initialize(host, port, db_key: bytes) -> None:
    """
    Sets up database globals

    Args:
        host: the host of the database
        port: the port of the database
        db_key: Keys used to encrypt and decrypt database entries
    """
    global key
    global fernet
    key = db_key
    fernet = Fernet(key)


def start(host, port, db_key: bytes) -> None:
    """
    Starts the database connection.

    Args:
        host: the database host
        port: the database port
        db_key: Keys used to encrypt and decrypt database entries

    Returns:
        Nothing
    """
    global key
    global fernet
    if key is None:
        key = db_key
    if fernet is None:
        fernet = Fernet(key)
    connect(db_name, tz_aware=True, host=host, port=port)


class ExtrovirtsDocumentMeta(TopLevelDocumentMetaclass):
    def __new__(mcs, name, bases, dct):
        return super().__new__(mcs, name, bases, dct)


class ExtrovirtsDocument(Document, metaclass=ExtrovirtsDocumentMeta):
    meta = {
        'abstract': True,
    }

    def __str__(self):
        return str(self.to_dict())

    def to_json(self) -> str:
        """
        Converts this document to json
        Returns:
            The converted document as json
        """
        return json.dumps(native_types(self), sort_keys=True, indent=4)

    def to_dict(self, dbref: bool=False) -> Dict:
        """
        Converts this document to a dictionary
        Args:
            dbref: If true, convert ObjectIds to DBRefs

        Returns:
            The converted document as a dictionary
        """
        dictified = self.to_mongo().to_dict()
        if dbref:
            for field, value in dictified.items():
                if isinstance(value, ObjectId) and field != '_id':
                    t = getattr(self, field)
                    if isinstance(t, ObjectId):
                        t = t.to_dbref()
                    dictified[field] = t

        return dictified

    def get(self, k, default=None):
        return self[k] if k in self else default

    @classmethod
    def existing_ids(cls, filters) -> Set[ObjectId]:
        return {doc['_id'] for doc in cls.objects().filter(**filters).as_pymongo()}


    @classmethod
    def get_special_field_decoders(cls) -> Dict[str, Callable]:
        """
        Returns the names of specially encoded fields (e.g. encrypted) fields for the
        collection and decoder functions to run on the field to make them intelligible.
        Returns: A dictionary with following schema: {'<field_name>': '<decoder callable>'}.
        If a collection has no fields that require special processing, an empty dict is
        returned.
        """
        special_field_decoders = {EncryptedDictField: EncryptedDictField.decrypt_bytes,
                                  EncryptedStringField: EncryptedStringField.decrypt_bytes}

        res = {}  # type: Dict[str, Callable]
        for field_name, field_type in cls._fields.items():  # type: str, BaseField
            if isinstance(field_type, tuple(special_field_decoders.keys())):
                res[field_name] = special_field_decoders[field_type.__class__]
            elif isinstance(field_type, ListField):
                # Also need to check inside of ListFields - e.g. ListField(EncryptedDictField())
                if isinstance(field_type.field, tuple(special_field_decoders.keys())):
                    decode = special_field_decoders[field_type.field.__class__]
                    res[field_name] = lambda x: [decode(i) for i in x]
            elif isinstance(field_type, DictField):
                if isinstance(field_type.field, tuple(special_field_decoders.keys())):
                    # This is needed to do things like DictField(EncryptedStringField())
                    raise NotImplementedError
        return res


def native_types(obj):
    """
    Converts an object to a json serializable type
    Args:
        obj: An object

    Returns:
        A JSON serializable type
    """
    if isinstance(obj, ExtrovirtsDocument):
        obj = obj.to_dict()
    elif isinstance(obj, BaseQuerySet):
        obj = list(obj)
    elif isinstance(obj, DBRef):
        obj = obj.id
    elif hasattr(obj, 'isoformat'):
        obj = obj.isoformat()

    if isinstance(obj, ObjectId):
        return str(obj)
    elif isinstance(obj, dict):
        return {native_types(k): native_types(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [native_types(x) for x in obj]
    elif isinstance(obj, bytes):
        if obj.startswith(prefix):
            decrypted_value = decrypt_value(obj).decode('ascii')
            try:
                # This was an EncyptedDictField
                return json.loads(decrypted_value)
            except ValueError:
                # This was an EncryptedStringField
                return decrypted_value
        # This was a byte field that wasn't encrypted
        return base64.b64encode(obj).decode('ascii')
    return obj


def subjectify(item):
    if isinstance(item, list):
        for i, sub_item in enumerate(item):
            item[i] = subjectify(sub_item)
    elif isinstance(item, dict):
        for k, v in item.items():
            item[k] = subjectify(v)
    elif isinstance(item, ObjectId):
        item = str(item)
    return item


class CustomSerializer(object):
    def serialize(self, value):
        pass

    def deserialize(self, value):
        pass


def serialize(item, serializers):
    for k, v in serializers.items():
        try:
            base = item
            parts = k.split('.')
            parents = parts[:-1] if len(parts) > 1 else []
            last = parts[-1]
            for attr in parents:
                base = base[attr]
            if isinstance(base, list):
                for i in base:
                    i[last] = v().serialize(i[last])
            else:
                base[last] = v().serialize(base[last])
        except KeyError:
            pass
    return item


def deserialize(item, serializers):
    for k, v in serializers.items():
        try:
            base = item
            parts = k.split('.')
            parents = parts[:-1] if len(parts) > 1 else []
            last = parts[-1]
            for attr in parents:
                base = base[attr]
            if isinstance(base, list):
                for i in base:
                    i[last] = v().deserialize(i[last])
            else:
                base[last] = v().deserialize(base[last])
        except KeyError:
            pass
    return item


def encrypt_value(value: Union[str, bytes]) -> Union[bytes, None]:
    """
    Encrypts a string with the database key from settings.yaml.

    Uses a prefix token to avoid double encryption. The encrypted text is
    base64 so these characters will never show up in the text.

    Args:
        value: the str or bytes to be encrypted

    Returns:
        an encrypted bytes-like object
    """
    # if value and not isinstance(value, bytes):
    #     # In Python3, the Cryptography lib expects 'bytes'-like input.  Attempt to encode str, etc. for this.
    #     value = bytes(value, 'utf-8')
    if isinstance(value, str):
        value = value.encode('utf-8')
    elif isinstance(value, bytes):
        pass
    else:
        raise ValueError("type(value) should be bytes or str not {}".format(type(value)))

    if value.startswith(prefix):  # Already encrypted
        return value
    else:
        return prefix + fernet.encrypt(value)


def decrypt_value(value: bytes) -> bytes:
    """
    Decrypts a bytes object with the database key from settings.yaml.

    Args:
        value: the bytes to be decrypted

    Returns:
        the decrypted bytes
    """
    if not isinstance(value, bytes):
        raise ValueError("type(value) should be bytes not {}".format(type(value)))
    if isinstance(value, str):
        # In Python3, the Cryptography lib expects 'bytes'-like input.  Attempt to encode str, etc. for this.
        value = value.encode('utf-8')

    if not value.startswith(prefix):
        return value   # value was not encrypted
    else:
        return fernet.decrypt(value[len(prefix):])


class EncryptedStringField(BinaryField):
    def __set__(self, instance, value: str) -> None:
        if isinstance(value, str):
            t = encrypt_value(value)
        elif value is None:
            t = value
        else:
            raise NotImplementedError("{}:{}".format(type(value), value))
        super(EncryptedStringField, self).__set__(instance, t)

    def __get__(self, instance, owner) -> Union[str, None]:
        value = super(EncryptedStringField, self).__get__(instance, owner)
        if value is None:
            return value
        else:
            return decrypt_value(value).decode('utf-8')

    def to_python(self, value: bytes) -> str:
        if isinstance(value, bytes):
            decrypted = decrypt_value(value)
            return decrypted.decode()
        elif isinstance(value, str):
            return value
        else:
            raise NotImplementedError("{}.to_python called with {} {}".format(self.__class__.__name__, type(value),
                                                                              value))

    @staticmethod
    def decrypt_bytes(value: bytes) -> str:
        if not isinstance(value, bytes):
            raise ValueError("type(value) should be bytes not {}".format(type(value)))
        return decrypt_value(value).decode()

    @staticmethod
    def encrypt_string(value: str) -> bytes:
        if not isinstance(value, str):
            raise ValueError("type(value) should be str not {}".format(type(value)))
        return encrypt_value(value.encode('utf-8'))


class EncryptedDictFieldProxy(UserDict):
    def __init__(self, instance: 'EncryptedDictField', name: str, *args, **kwargs):
        self._instance = instance
        self._name = name
        super().__init__(*args, **kwargs)

    def __setitem__(self, key, value):
        # update self.data
        super().__setitem__(key, value)
        # update mongoengine
        setattr(self._instance, self._name, self.data)  # type: EncryptedDictField


class EncryptedDictField(EncryptedStringField):
    """
    Allows dictionary objects to be encrypted in Mongo and retrieved as Dictionary-like objects.
    This field works works by serializing dictionaries to json and storing them in EncryptedStringFields
    which in mongo are just binary blobs.  Dictionary-like access in Python is through the
    :class:`.EncryptedDictFieldProxy` class, which is a UserDict that sends changes back to mongo via
    EncryptedDictField's __set__ method.  WARNING: This is similar to how mongoengine handles normal dictionaries
    with :class:`mongoengine.ComplexBaseField` and :class:`mongoengine.BaseDict`, however, it is currently
     much less robust: changes to nested dictionaries will not be saved in MongoDB.
    """
    def __get__(self, instance, owner):
        res = super().__get__(instance, owner)

        if res is None:
            return res
        elif isinstance(res, str) and res != 'None':
            dictified = json.loads(res)
            return EncryptedDictFieldProxy(instance, self.name, dictified.items())
        elif isinstance(res, dict):
            return EncryptedDictFieldProxy(instance, self.name, res.items())
        else:
            raise NotImplementedError("Unexpected return value {} from {}.__get__".format(res, super().__name__))

    def __set__(self, instance, value: EncryptedDictFieldProxy):
        if isinstance(value, EncryptedDictFieldProxy):
            v = json.dumps(value.data)
        elif isinstance(value, dict):
            v = json.dumps(value)
        elif value is None:
            v = value
        else:
            raise NotImplementedError("{}:{}".format(type(value), value))
        super().__set__(instance, v)

    def to_python(self, value: Dict):
        if value is None:
            return value
        elif isinstance(value, dict):
            return value
        elif isinstance(value, bytes):
            serialized = super().to_python(value)
            return json.loads(serialized)
        elif isinstance(value, str):
            return json.loads(value)
        else:
            raise NotImplementedError("{}.to_python called with {} {}".format(self.__class__.__name__, type(value),
                                                                              value))

    def to_mongo(self, value):
        if isinstance(value, bytes):
            return value
        else:
            raise NotImplementedError("{}.to_mongo called with {} {}".format(self.__class__.__name__, type(value),
                                                                             value))

    @staticmethod
    def decrypt_bytes(value: bytes) -> Dict:
        if not isinstance(value, bytes):
            raise ValueError("type(value) should be bytes, not {}".format(type(value)))
        return json.loads(EncryptedStringField.decrypt_bytes(value))

    @staticmethod
    def encrypt_dict(value: dict) -> bytes:
        if not isinstance(value, dict):
            raise ValueError("type(value) should be dict, not {}".format(type(value)))
        return EncryptedStringField.encrypt_string(json.dumps(value))

