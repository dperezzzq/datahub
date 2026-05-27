from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# Usuario
class Usuario(db.Model):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    apellido = db.Column(db.String(100), nullable=False)
    user = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    contrasena_hash = db.Column(db.String(200))  # opcional si usas autenticación local
    es_admin = db.Column(db.Boolean, default=False)
    ver_metricas = db.Column(db.Boolean, default=False)
    ver_solicitudes_reportes = db.Column(db.Boolean, default=False)

    accesos = db.relationship('AccesoReporte', back_populates='usuario', cascade="all, delete")

# Área
class Area(db.Model):
    __tablename__ = 'areas'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), unique=True, nullable=False)

    reportes = db.relationship('Reporte', back_populates='area', cascade="all, delete")

# Reporte
class Reporte(db.Model):
    __tablename__ = 'reportes'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    area_id = db.Column(db.Integer, db.ForeignKey('areas.id'), nullable=False)

    area = db.relationship('Area', back_populates='reportes')
    accesos = db.relationship('AccesoReporte', back_populates='reporte', cascade="all, delete")
    bitacora = db.relationship('BitacoraReporte', back_populates='reporte', cascade="all, delete")

# Accesos
class AccesoReporte(db.Model):
    __tablename__ = 'accesos_reportes'
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    reporte_id = db.Column(db.Integer, db.ForeignKey('reportes.id'), nullable=False)

    usuario = db.relationship('Usuario', back_populates='accesos')
    reporte = db.relationship('Reporte', back_populates='accesos')

# Bitácora de Reportes
class BitacoraReporte(db.Model):
    __tablename__ = 'bitacora_reportes'
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    reporte_id = db.Column(db.Integer, db.ForeignKey('reportes.id'), nullable=False)
    fecha_hora = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    usuario = db.relationship('Usuario')
    reporte = db.relationship('Reporte', back_populates='bitacora')

# Solicitud de Reporte
class SolicitudReporte(db.Model):
    __tablename__ = 'solicitud_reporte'

    id = db.Column(db.Integer, primary_key=True)
    reporte = db.Column(db.String(255), nullable=False)
    area = db.Column(db.String(100), nullable=False)
    fecha_solicitud = db.Column(db.DateTime, nullable=False)
    solicitado_por = db.Column(db.String(100), nullable=False)
    prioridad = db.Column(db.Enum('Alta', 'Media', 'Baja'), nullable=False, default='Media')
    fecha_entregado = db.Column(db.DateTime, nullable=True)
    encargado = db.Column(db.String(100), nullable=True)
    complejidad = db.Column(db.Enum('Alta', 'Media', 'Baja'), nullable=False, default='Media')
    progreso = db.Column(db.Integer, nullable=False, default=0)  # porcentaje (0-100)
    observaciones = db.Column(db.Text, nullable=True)

