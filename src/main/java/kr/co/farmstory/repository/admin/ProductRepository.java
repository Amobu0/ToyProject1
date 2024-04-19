package kr.co.farmstory.repository.admin;


import kr.co.farmstory.entity.Product;
import org.springframework.data.jpa.repository.JpaRepository;


/**
 * SpringDataJPA 자동으로 빈등록해줌
 */
public interface ProductRepository extends JpaRepository<Product, Long> {

}
