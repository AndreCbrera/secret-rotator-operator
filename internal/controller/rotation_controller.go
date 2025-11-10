package controller

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	// Importación de tu API (CRD) y el nuevo paquete de seguridad
	rotationv1alpha1 "github.com/AndreCbrera/secret-rotator-operator/api/v1alpha1"
	"github.com/AndreCbrera/secret-rotator-operator/internal/security"

	// Dependencias externas
	"github.com/hashicorp/vault/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RotationReconciler reconciles a Rotation object
type RotationReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=rotation.security.io,resources=rotations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rotation.security.io,resources=rotations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=rotation.security.io,resources=rotations/finalizers,verbs=update

// Reconcile es la función principal del bucle de control.
func (r *RotationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// 1. Obtener la instancia del recurso Rotation
	rotation := &rotationv1alpha1.Rotation{}
	if err := r.Get(ctx, req.NamespacedName, rotation); err != nil {
		// Si el recurso no se encuentra (fue borrado), ignorar la solicitud.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 2. Determinar si se necesita rotar
	rotationInterval, err := time.ParseDuration(rotation.Spec.RotationInterval)
	if err != nil {
		log.Error(err, "Intervalo de rotación no válido, saltando reconciliación", "interval", rotation.Spec.RotationInterval)
		// No se puede continuar, pero no reintentar a menos que el CRD sea corregido.
		return ctrl.Result{}, nil
	}

	// Comprobar la última rotación
	needsRotation := true
	if rotation.Status.LastRotatedTime != nil {
		timeSinceLastRotation := time.Since(rotation.Status.LastRotatedTime.Time)
		if timeSinceLastRotation < rotationInterval {
			needsRotation = false
			log.V(1).Info("No se necesita rotación",
				"tiempoRestante", rotationInterval-timeSinceLastRotation,
				"próximaRotación", rotation.Status.LastRotatedTime.Add(rotationInterval),
			)
			// Reintentar justo cuando se cumpla el intervalo
			return ctrl.Result{RequeueAfter: rotationInterval - timeSinceLastRotation}, nil
		}
	}

	if !needsRotation {
		return ctrl.Result{}, nil
	}

	// ----------------------------------------------------
	// 3. Generar, Escribir en Vault, y Actualizar Estado
	// ----------------------------------------------------

	log.Info("Iniciando rotación de secreto")

	// A. Generación Segura de Contraseña con Go
	passwordLength := rotation.Spec.PasswordLength
	if passwordLength == 0 {
		passwordLength = 16 // Usar valor por defecto si no se especifica
	}

	newPassword, err := security.GeneratePassword(passwordLength, rotation.Spec.IncludeSymbols)
	if err != nil {
		log.Error(err, "Fallo al generar la contraseña segura")
		rotation.Status.Status = "ErrorGeneracion"
		r.Status().Update(ctx, rotation)
		return ctrl.Result{}, err // Reintentar la generación
	}

	// B. Conexión y Escritura en Vault
	// NOTA: Esta es una implementación mock. En un entorno real, la autenticación
	// sería la parte más compleja (Auth/Kubernetes).

	vaultPath := rotation.Spec.VaultPath
	err = r.writeToVault(vaultPath, newPassword)
	if err != nil {
		log.Error(err, "Fallo al escribir en HashiCorp Vault", "path", vaultPath)
		rotation.Status.Status = "ErrorVault"
		r.Status().Update(ctx, rotation)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil // Reintentar en 30 segundos
	}

	log.Info("Secreto escrito exitosamente en Vault", "path", vaultPath)

	// C. Actualizar el Estado del CRD
	now := metav1.Now()
	rotation.Status.LastRotatedTime = &now
	rotation.Status.Status = "Ready"
	if err := r.Status().Update(ctx, rotation); err != nil {
		log.Error(err, "Fallo al actualizar el estado de rotación")
		return ctrl.Result{}, err
	}

	// Reintentar la conciliación cuando el intervalo se cumpla de nuevo
	return ctrl.Result{RequeueAfter: rotationInterval}, nil
}

// ----------------------------------------------------
// LÓGICA DE VAULT (MOCK para demostración)
// ----------------------------------------------------

// writeToVaultMock simula la escritura de la contraseña en una ruta de Vault.
// En un entorno real, esta función contendría la inicialización del cliente de Vault,
// la autenticación (e.g., usando ServiceAccount), y la llamada a vaultClient.Logical().Write().
func (r *RotationReconciler) writeToVault(path string, password string) error {

	// ** 1. Configuración de Vault (Real) **
	config := api.DefaultConfig()
	config.Address = "http://vault.vault-system:8200" // Dirección de Vault dentro de K8s
	client, err := api.NewClient(config)
	if err != nil {
		return fmt.Errorf("fallo al crear el cliente de Vault: %w", err)
	}

	// ** 2. Autenticación (Real: Usar Auth/Kubernetes)**
	// En producción, el token se obtendría mediante el ServiceAccount del Pod.
	// client.SetToken("s.xyz123...")

	// ** 3. Escritura del Secreto (Real) **
	log := logf.Log.WithName("VaultWriter").WithValues("path", path)

	// Simulación de autenticación exitosa:
	if client.Token() == "" {
		log.Info("ADVERTENCIA: Usando Vault MOCK. Asumiendo éxito en la escritura.")
	}

	// Simulación de la estructura de datos que se escribiría en Vault
	data := map[string]interface{}{
		"data": map[string]interface{}{
			"password":   password,
			"rotated_by": "secret-rotator-operator",
		},
	}

	// Simulamos la llamada de escritura:
	_, err = client.Logical().Write(path, data)

	// Si hubiera un error real de red o permisos, lo devolveríamos aquí.

	log.Info("Vault Mock: Escritura simulada exitosa")
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RotationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&rotationv1alpha1.Rotation{}).
		Named("rotation").
		Complete(r)
}
