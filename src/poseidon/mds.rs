use ark_ff::PrimeField;
use crate::poseidon::matrix::Matrix;

#[derive(Clone, Debug, PartialEq)]
pub struct MdsMatrices<F: PrimeField> {
    pub m: Matrix<F>,
    pub m_inv: Matrix<F>,
    pub m_hat: Matrix<F>,
    pub m_hat_inv: Matrix<F>,
    pub m_prime: Matrix<F>,
    pub m_double_prime: Matrix<F>,
}

impl<F: PrimeField> MdsMatrices<F> {
    /// Derive MDS matrix of size `dim*dim` and relevant things
    pub fn new(dim: usize) -> Self {
        let m = Self::generate_mds(dim);
        let m_inv = m.invert().expect("Derived MDS matrix is not invertible");
        let m_hat = m.minor(0, 0);
        let m_hat_inv = m_hat.invert().expect("Derived MDS matrix is not correct");
        let m_prime = Self::make_prime(&m);
        let m_double_prime = Self::make_double_prime(&m, &m_hat_inv);
        MdsMatrices {
            m,
            m_inv,
            m_hat,
            m_hat_inv,
            m_prime,
            m_double_prime,
        }
    }

    fn generate_mds(t: usize) -> Matrix<F> {
        let xs: Vec<F> = (0..t as u64).map(F::from).collect();
        let ys: Vec<F> = (t as u64..2 * t as u64).map(F::from).collect();

        let matrix = xs
            .iter()
            .map(|xs_item| {
                ys.iter()
                    .map(|ys_item| {
                        // Generate the entry at (i,j)
                        let mut tmp = *xs_item;
                        tmp.add_assign(ys_item);
                        tmp.inverse().unwrap()
                    })
                    .collect()
            }).collect::<Matrix<F>>();

        debug_assert!(matrix.is_invertible());
        debug_assert_eq!(matrix, matrix.transpose());
        matrix
    }

    fn make_prime(m: &Matrix<F>) -> Matrix<F> {
        m.iter_rows().enumerate().map(|(i, row)|
            match i {
                0 => {
                    let mut new_row = vec![F::zero(); row.len()];
                    new_row[0] = F::one();
                    new_row
                }
                _ => {
                    let mut new_row = vec![F::zero(); row.len()];
                    new_row[1..].copy_from_slice(&row[1..]);
                    new_row
                }
            }
        ).collect()
    }

    fn make_double_prime(m: &Matrix<F>, m_hat_inv: &Matrix<F>) -> Matrix<F> {
        let (v, w) = Self::make_v_w(m);
        let w_hat = m_hat_inv.right_apply(&w);

        m.iter_rows().enumerate().map(|(i, row)| match i {
            0 => {
                let mut new_row = Vec::with_capacity(row.len());
                new_row.push(row[0]);
                new_row.extend(&v);
                new_row
            }
            _ => {
                let mut new_row = vec![F::zero(); row.len()];
                new_row[0] = w_hat[i - 1];
                new_row[i] = F::one();
                new_row
            }
        }).collect()
    }

    fn make_v_w(m: &Matrix<F>) -> (Vec<F>, Vec<F>) {
        let v = m[0][1..].to_vec();
        let w = m.iter_rows().skip(1).map(|column| column[0]).collect();
        (v, w)
    }
}

#[cfg(test)]
mod tests {
    use ark_std::{test_rng, UniformRand};
    use crate::poseidon::mds::MdsMatrices;
    use ark_bls12_381::Fr;

    #[test]
    fn test_mds_matrices_creation() {
        for i in 2..5 {
            test_mds_matrices_creation_aux(i);
        }
    }

    fn test_mds_matrices_creation_aux(width: usize) {
        let MdsMatrices {
            m,
            m_inv,
            m_hat,
            m_hat_inv,
            m_prime,
            m_double_prime,
        } = MdsMatrices::<Fr>::new(width);

        for i in 0..m_hat.num_rows() {
            for j in 0..m_hat.num_columns() {
                assert_eq!(m[i + 1][j + 1], m_hat[i][j], "MDS minor has wrong value.");
            }
        }

        // M^-1 x M = I
        assert!(m_inv.mul_mat(&m).unwrap().is_identity());

        // M' x M'' = M
        assert_eq!(m, m_prime.mul_mat(&m_double_prime).unwrap());
    }

    #[test]
    fn test_swapping() {
        test_swapping_aux(3)
    }

    fn test_swapping_aux(width: usize) {
        let mut rng = test_rng();
        let mds = MdsMatrices::<Fr>::new(width);

        let base = (0..width).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let x = {
            let mut x = base.clone();
            x[0] = Fr::rand(&mut rng);
            x
        };
        let y = {
            let mut y = base.clone();
            y[0] = Fr::rand(&mut rng);
            y
        };

        let qx = mds.m_prime.right_apply(&x);
        let qy = mds.m_prime.right_apply(&y);
        assert_eq!(qx[0], x[0]);
        assert_eq!(qy[0], y[0]);
        assert_eq!(qx[1..], qy[1..]);

        let mx = mds.m.left_apply(&x);
        let m1_m2_x = mds.m_prime.left_apply(&mds.m_double_prime.left_apply(&x));
        assert_eq!(mx, m1_m2_x);

        let xm = mds.m.right_apply(&x);
        let x_m1_m2 = mds.m_double_prime.right_apply(&mds.m_prime.right_apply(&x));
        assert_eq!(xm, x_m1_m2);

    }
}


