#ifndef ML_EVASION_ENGINE_HPP
#define ML_EVASION_ENGINE_HPP
#include "stealth_macros.hpp"
// Security Components Integration - Missing Critical Dependencies
#include "stealth_scrubber.hpp"
#include "trace_cleaner.hpp"
#include "metadata_cleaner.hpp"
#include "memory_sanitizer.hpp"
#include "pdf_integrity_checker.hpp"

#include <vector>
#include <map>
#include <string>
#include <random>
#include <memory>

class MLEvasionEngine {
public:
    struct MLModelSignature {
        std::string model_type;
        std::vector<std::string> feature_extractors;
        std::vector<double> classification_boundaries;
        std::map<std::string, double> feature_weights;
        double confidence_threshold;
        std::vector<std::string> known_vulnerabilities;
    };

    struct AdversarialPattern {
        std::vector<uint8_t> pattern_bytes;
        std::string target_model;
        double effectiveness_score;
        std::vector<size_t> injection_positions;
        std::string evasion_technique;
    };

    struct BehavioralSignature {
        std::map<std::string, double> file_characteristics;
        std::vector<double> temporal_patterns;
        std::map<std::string, std::string> metadata_fingerprints;
        double authenticity_score;
        std::string human_behavior_profile;
    };

    // Core ML evasion functions
    void disrupt_classification_features();
    void inject_adversarial_pattern_noise();
    void mask_automated_processing_indicators();
    void simulate_human_document_interaction_patterns();

    // Critical Method - Integration Complete
    std::vector<uint8_t> analyze_and_evade(const std::vector<uint8_t>& pdf_data);

    // ML model analysis and evasion
    MLModelSignature analyze_target_ml_model(const std::string& model_type);
    std::vector<AdversarialPattern> generate_adversarial_patterns(const MLModelSignature& target_model);
    void inject_adversarial_samples(std::vector<uint8_t>& pdf_data, const std::vector<AdversarialPattern>& patterns);
    
    // Feature disruption techniques
    void disrupt_statistical_features(std::vector<uint8_t>& pdf_data);
    void disrupt_structural_features(std::vector<uint8_t>& pdf_data);
    void disrupt_metadata_features(std::vector<uint8_t>& pdf_data);
    void disrupt_temporal_features(std::vector<uint8_t>& pdf_data);
    void disrupt_content_features(std::vector<uint8_t>& pdf_data);
    
    // Behavioral pattern simulation
    BehavioralSignature generate_human_behavior_profile();
    void inject_human_interaction_artifacts(std::vector<uint8_t>& pdf_data, const BehavioralSignature& profile);
    void simulate_organic_document_evolution(std::vector<uint8_t>& pdf_data);
    void replicate_natural_editing_patterns(std::vector<uint8_t>& pdf_data);
    
    // Classification boundary manipulation
    void identify_classification_boundaries(const MLModelSignature& model);
    void generate_boundary_crossing_patterns(const MLModelSignature& model);
    void inject_boundary_manipulation_noise(std::vector<uint8_t>& pdf_data, const MLModelSignature& model);
    
    // AI/ML detection evasion
    void evade_neural_network_detection(std::vector<uint8_t>& pdf_data);
    void evade_decision_tree_detection(std::vector<uint8_t>& pdf_data);
    void evade_svm_detection(std::vector<uint8_t>& pdf_data);
    void evade_ensemble_model_detection(std::vector<uint8_t>& pdf_data);
    void evade_deep_learning_detection(std::vector<uint8_t>& pdf_data);
    
    // Feature masking techniques
    void mask_entropy_based_features(std::vector<uint8_t>& pdf_data);
    void mask_n_gram_features(std::vector<uint8_t>& pdf_data);
    void mask_frequency_analysis_features(std::vector<uint8_t>& pdf_data);
    void mask_compression_ratio_features(std::vector<uint8_t>& pdf_data);
    void mask_file_size_features(std::vector<uint8_t>& pdf_data);
    
    // Advanced evasion techniques
    void apply_gradient_descent_evasion(std::vector<uint8_t>& pdf_data, const MLModelSignature& model);
    void apply_genetic_algorithm_evasion(std::vector<uint8_t>& pdf_data, const MLModelSignature& model);
    void apply_adversarial_training_evasion(std::vector<uint8_t>& pdf_data, const MLModelSignature& model);
    void apply_model_inversion_evasion(std::vector<uint8_t>& pdf_data, const MLModelSignature& model);
    
    // Real-time adaptation
    void adapt_to_new_ml_models(const std::vector<MLModelSignature>& new_models);
    void update_evasion_strategies(const std::string& model_update);
    void learn_from_detection_feedback(const std::string& detection_result);
    
    // Validation and testing
    bool validate_ml_evasion_effectiveness(const std::vector<uint8_t>& pdf_data);
    double calculate_evasion_confidence(const std::vector<uint8_t>& pdf_data, const MLModelSignature& model);
    std::vector<std::string> test_against_ml_models(const std::vector<uint8_t>& pdf_data);
    
    // MISSING METHOD - Integration Fix for PDF_Byte_To_Byte_Fidelity_Strategy.md
    double calculate_evasion_effectiveness(const std::vector<uint8_t>& pdf_data);
    
    // Additional analysis methods - Integration Complete
    MLAnalysisResult analyze_ml_detection_patterns(const std::vector<uint8_t>& pdf_data);
    void apply_enhanced_evasion_techniques(std::vector<uint8_t>& pdf_data);
    
    // Configuration
    void set_target_ml_models(const std::vector<std::string>& models);
    void set_evasion_aggressiveness(EvasionAggressiveness level);
    void set_behavioral_profile(const std::string& profile_type);

    enum class EvasionAggressiveness {
        SUBTLE,         // Minimal changes to avoid basic ML detection
        MODERATE,       // Balanced approach for general ML evasion
        AGGRESSIVE,     // Strong evasion for advanced ML models
        MAXIMUM         // Full spectrum evasion for all known ML techniques
    };

private:
    std::vector<std::string> target_ml_models_;
    EvasionAggressiveness evasion_level_ = EvasionAggressiveness::MAXIMUM;
    std::string behavioral_profile_type_ = "professional_user";
    
    // ML model database
    std::map<std::string, MLModelSignature> known_ml_models_;
    std::map<std::string, std::vector<AdversarialPattern>> adversarial_pattern_database_;
    std::map<std::string, BehavioralSignature> behavioral_profile_database_;
    
    // Evasion technique database
    std::vector<std::function<void(std::vector<uint8_t>&)>> evasion_techniques_;
    std::map<std::string, std::vector<double>> feature_disruption_weights_;
    
    // Random number generation for adversarial patterns
    std::mt19937 adversarial_generator_;
    
    // Internal helper functions
    void initialize_ml_model_database();
    void initialize_adversarial_pattern_database();
    void initialize_behavioral_profile_database();
    void initialize_evasion_technique_database();
    
    // Feature analysis helpers
    std::vector<double> extract_statistical_features(const std::vector<uint8_t>& data);
    std::vector<double> extract_structural_features(const std::vector<uint8_t>& data);
    std::vector<double> extract_metadata_features(const std::vector<uint8_t>& data);
    std::vector<double> extract_temporal_features(const std::vector<uint8_t>& data);
    
    // Adversarial generation helpers
    std::vector<uint8_t> generate_adversarial_noise(size_t length, const MLModelSignature& target);
    std::vector<size_t> identify_optimal_injection_points(const std::vector<uint8_t>& data, const MLModelSignature& target);
    double calculate_adversarial_effectiveness(const std::vector<uint8_t>& original, const std::vector<uint8_t>& modified, const MLModelSignature& target);
    
    // Behavioral simulation helpers
    std::vector<uint8_t> simulate_user_editing_session(const std::vector<uint8_t>& data);
    std::vector<uint8_t> simulate_software_workflow_artifacts(const std::vector<uint8_t>& data);
    std::vector<uint8_t> simulate_temporal_document_aging(const std::vector<uint8_t>& data);
    
    // Classification boundary helpers
    std::vector<double> map_feature_space(const std::vector<uint8_t>& data);
    std::vector<double> find_decision_boundary(const MLModelSignature& model);
    std::vector<uint8_t> generate_boundary_crossing_modification(const std::vector<uint8_t>& data, const std::vector<double>& boundary);
    
    // Validation helpers
    bool test_against_specific_model(const std::vector<uint8_t>& data, const MLModelSignature& model);
    double simulate_model_confidence(const std::vector<uint8_t>& data, const MLModelSignature& model);
    std::vector<std::string> identify_remaining_ml_signatures(const std::vector<uint8_t>& data);
};

#endif // ML_EVASION_ENGINE_HPP
